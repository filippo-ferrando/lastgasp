package wire

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
)

// Version 5 packets use a Noise NNpsk0 handshake for forward secrecy, see docs/forward-secrecy.md.
const (
	VersionFS = 5

	TypeInit  uint8 = 1 // handshake init, agent to server
	TypeReply uint8 = 2 // handshake reply, server to agent
	TypeData  uint8 = 3 // record or heartbeat, agent to server
	TypeAck   uint8 = 4 // ack, server to agent

	// Version 5 adds the type and the session ID to the clear header.
	headerFS = headerFixed + 1 + 4

	// RekeyAfter, RejectAfter and HandshakeRetry are the WireGuard timers.
	RekeyAfter     = 2 * time.Minute
	RejectAfter    = 3 * time.Minute
	HandshakeRetry = time.Second

	replayWords = 64
	// ReplayWindow is how far behind the highest counter a data packet may arrive.
	ReplayWindow = replayWords * 64
)

var (
	ErrReplay  = errors.New("wire: replayed packet")
	ErrSession = errors.New("wire: unknown session")
)

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// random makes session IDs and handshake keys. Fuzz tests replace it, so every process makes the same handshake.
var random io.Reader = rand.Reader

// PacketVersion returns the version of a lastgasp packet, or 0 for anything else.
func PacketVersion(buf []byte) uint8 {
	if len(buf) < 5 || string(buf[:4]) != magic {
		return 0
	}
	return buf[4]
}

// Header is the clear part of a version 5 packet.
type Header struct {
	Host     string
	BootID   [16]byte
	Instance uint64
	Type     uint8
	Session  uint32
	Counter  uint64
	len      int
}

func (h *Header) encode() []byte {
	b := make([]byte, 0, MaxPacket)
	b = append(b, magic...)
	b = append(b, VersionFS, byte(len(h.Host)))
	b = append(b, h.Host...)
	b = append(b, h.BootID[:]...)
	b = binary.BigEndian.AppendUint64(b, h.Instance)
	b = append(b, h.Type)
	b = binary.BigEndian.AppendUint32(b, h.Session)
	return binary.BigEndian.AppendUint64(b, h.Counter)
}

func (h *Header) sameRun(o Header) bool {
	return h.Host == o.Host && h.BootID == o.BootID && h.Instance == o.Instance && h.Session == o.Session
}

// ParseHeader reads the clear header of a version 5 packet.
func ParseHeader(buf []byte) (Header, error) {
	var h Header
	if PacketVersion(buf) == 0 {
		return h, ErrMalformed
	}
	if buf[4] != VersionFS {
		return h, ErrVersion
	}
	if len(buf) < 6 {
		return h, ErrMalformed
	}
	hostLen := int(buf[5])
	h.len = headerFS + hostLen
	if hostLen == 0 || len(buf) < h.len+TagSize {
		return h, ErrMalformed
	}
	h.Host = string(buf[6 : 6+hostLen])
	if !ValidHost(h.Host) {
		return h, ErrHost
	}
	r := reader{b: buf[6+hostLen : h.len]}
	copy(h.BootID[:], r.take(16))
	h.Instance = r.u64()
	h.Type = r.u8()
	h.Session = r.u32()
	h.Counter = r.u64()
	return h, nil
}

// newHandshake prepares one side of a handshake. The prologue ties it to one agent run and session.
func newHandshake(key []byte, h Header, initiator bool) (*noise.HandshakeState, error) {
	psk, err := hkdf.Key(sha256.New, key, nil, "lastgasp v5 psk", 32)
	if err != nil {
		return nil, err
	}
	pro := make([]byte, 0, 64+len(h.Host))
	pro = append(pro, "lastgasp v5"...)
	pro = append(pro, byte(len(h.Host)))
	pro = append(pro, h.Host...)
	pro = append(pro, h.BootID[:]...)
	pro = binary.BigEndian.AppendUint64(pro, h.Instance)
	pro = binary.BigEndian.AppendUint32(pro, h.Session)
	return noise.NewHandshakeState(noise.Config{CipherSuite: suite, Random: random, Pattern: noise.HandshakeNN,
		Initiator: initiator, Prologue: pro, PresharedKey: psk, PresharedKeyPlacement: 0})
}

// wipe clears the private key of a finished handshake, so the session cannot be derived again.
func wipe(hs *noise.HandshakeState) {
	clear(hs.LocalEphemeral().Private)
}

// Handshake is a handshake started by the agent, waiting for the server reply.
type Handshake struct {
	h  Header
	hs *noise.HandshakeState
}

// StartHandshake makes a handshake init for one agent run. number must grow with every handshake of the run.
func StartHandshake(key []byte, host string, bootID [16]byte, instance, number uint64) (*Handshake, []byte, error) {
	if !ValidHost(host) {
		return nil, nil, ErrHost
	}
	var id [4]byte
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return nil, nil, err
	}
	h := Header{Host: host, BootID: bootID, Instance: instance, Type: TypeInit, Session: binary.BigEndian.Uint32(id[:])}
	hs, err := newHandshake(key, h, true)
	if err != nil {
		return nil, nil, err
	}
	b, _, _, err := hs.WriteMessage(h.encode(), binary.BigEndian.AppendUint64(nil, number))
	if err != nil {
		return nil, nil, err
	}
	return &Handshake{h: h, hs: hs}, b, nil
}

// Session returns the session ID the handshake will have.
func (k *Handshake) Session() uint32 { return k.h.Session }

// Finish checks the server reply and returns the session. A reply that fails leaves the handshake usable.
func (k *Handshake) Finish(buf []byte) (*Session, error) {
	h, err := ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	// The counter is not used in handshakes. It must be 0, so a reply has one valid form only.
	if k.hs == nil || h.Type != TypeReply || h.Counter != 0 || !h.sameRun(k.h) {
		return nil, ErrAuth
	}
	payload, send, recv, err := k.hs.ReadMessage(nil, buf[h.len:])
	if err != nil || send == nil || len(payload) != 0 {
		return nil, ErrAuth
	}
	wipe(k.hs)
	k.hs = nil
	return newSession(k.h, send.Cipher(), recv.Cipher()), nil
}

// Init is a checked handshake init, waiting for the server to answer it.
type Init struct {
	Header
	// Number grows with every handshake of an agent run, so a replayed init can be refused.
	Number uint64
	hs     *noise.HandshakeState
}

// ReadInit checks a handshake init with the key of its host. The key exchange happens later in
// Accept, so a packet without the right key costs only one decrypt.
func ReadInit(buf []byte, keyFor func(host string) []byte) (*Init, error) {
	h, err := ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	if h.Type != TypeInit || h.Counter != 0 {
		return nil, ErrMalformed
	}
	key := keyFor(h.Host)
	if key == nil {
		return nil, ErrUnknownHost
	}
	hs, err := newHandshake(key, h, false)
	if err != nil {
		return nil, err
	}
	payload, _, _, err := hs.ReadMessage(nil, buf[h.len:])
	if err != nil {
		return nil, ErrAuth
	}
	if len(payload) != 8 {
		return nil, ErrMalformed
	}
	return &Init{Header: h, Number: binary.BigEndian.Uint64(payload), hs: hs}, nil
}

// Accept makes the reply to the init and the session it starts.
func (in *Init) Accept() (*Session, []byte, error) {
	if in.hs == nil {
		return nil, nil, ErrAuth
	}
	h := in.Header
	h.Type, h.Counter = TypeReply, 0
	b, recv, send, err := in.hs.WriteMessage(h.encode(), nil)
	if err != nil {
		return nil, nil, err
	}
	wipe(in.hs)
	in.hs = nil
	return newSession(in.Header, send.Cipher(), recv.Cipher()), b, nil
}

// Session holds the two transport keys of one handshake, one per direction.
type Session struct {
	ID       uint32
	Host     string
	BootID   [16]byte
	Instance uint64

	send, recv noise.Cipher
	counter    atomic.Uint64
	mu         sync.Mutex
	window     replayWindow
}

func newSession(h Header, send, recv noise.Cipher) *Session {
	return &Session{ID: h.Session, Host: h.Host, BootID: h.BootID, Instance: h.Instance, send: send, recv: recv}
}

func (s *Session) seal(typ uint8, body []byte) []byte {
	h := Header{Host: s.Host, BootID: s.BootID, Instance: s.Instance, Type: typ, Session: s.ID, Counter: s.counter.Add(1)}
	b := h.encode()
	// The counter is the nonce. It is sent in clear, so lost or reordered packets do not matter.
	return s.send.Encrypt(b, h.Counter, b, body)
}

func (s *Session) open(buf []byte, typ uint8) (Header, []byte, error) {
	h, err := ParseHeader(buf)
	if err != nil {
		return h, nil, err
	}
	if h.Type != typ || h.Host != s.Host || h.BootID != s.BootID || h.Instance != s.Instance || h.Session != s.ID {
		return h, nil, ErrSession
	}
	inner, err := s.recv.Decrypt(nil, h.Counter, buf[:h.len], buf[h.len:])
	if err != nil {
		return h, nil, ErrAuth
	}
	return h, inner, nil
}

// Seal encodes and encrypts the record or heartbeat p. Host, BootID and Instance are taken from the session.
func (s *Session) Seal(p *Packet) ([]byte, error) {
	p.Host, p.BootID, p.Instance, p.Version = s.Host, s.BootID, s.Instance, VersionFS
	inner, err := encodeInner(p, VersionFS)
	if err != nil {
		return nil, err
	}
	if headerFS+len(s.Host)+len(inner)+TagSize > MaxPacket {
		return nil, ErrTooLarge
	}
	return s.seal(TypeData, inner), nil
}

// Open checks and decrypts a data packet of the session. A repeated or too old counter gives ErrReplay.
func (s *Session) Open(buf []byte) (*Packet, error) {
	h, inner, err := s.open(buf, TypeData)
	if err != nil {
		return nil, err
	}
	// The window moves only after the packet proved genuine.
	s.mu.Lock()
	fresh := s.window.accept(h.Counter)
	s.mu.Unlock()
	if !fresh {
		return nil, ErrReplay
	}
	p := &Packet{Version: VersionFS, Host: s.Host, BootID: s.BootID, Instance: s.Instance}
	if err := decodeInner(p, inner); err != nil {
		return nil, err
	}
	return p, nil
}

// SealAck builds the answer to the heartbeat p. upto and missing tell what the server received.
func (s *Session) SealAck(p *Packet, upto uint64, missing []Range) ([]byte, error) {
	if len(missing) > MaxAckRanges {
		return nil, ErrTooLarge
	}
	return s.seal(TypeAck, encodeAck(p, VersionFS, upto, missing)), nil
}

// OpenAck checks an ack of the session. The agent refuses acks to old heartbeats by their SentAt.
func (s *Session) OpenAck(buf []byte) (Ack, error) {
	_, inner, err := s.open(buf, TypeAck)
	if err != nil {
		return Ack{}, err
	}
	return decodeAck(inner, VersionFS)
}

// replayWindow remembers which counters near the highest one were seen, as in RFC 6479.
type replayWindow struct {
	top  uint64
	bits [replayWords]uint64
}

func (w *replayWindow) flip(n uint64, set bool) {
	i, m := (n/64)%replayWords, uint64(1)<<(n%64)
	if set {
		w.bits[i] |= m
	} else {
		w.bits[i] &^= m
	}
}

// accept reports whether counter n is new, and marks it as seen.
func (w *replayWindow) accept(n uint64) bool {
	if n == 0 {
		return false
	}
	if n > w.top {
		if n-w.top >= ReplayWindow {
			clear(w.bits[:])
		} else {
			for i := w.top + 1; i < n; i++ {
				w.flip(i, false)
			}
		}
		w.top = n
		w.flip(n, true)
		return true
	}
	if w.top-n >= ReplayWindow || w.bits[(n/64)%replayWords]&(uint64(1)<<(n%64)) != 0 {
		return false
	}
	w.flip(n, true)
	return true
}
