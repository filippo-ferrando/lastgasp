// Package wire defines the encrypted UDP packet shared by the agent and the server.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

const (
	magic = "LGP1"
	// Version 3 adds the oldest held seq to heartbeats and the receive state to acks.
	// Version 4 adds the agent version to heartbeats.
	version = 4
	// minVersion is the oldest version still accepted, so agents can be upgraded after the server.
	minVersion = 2

	// TagSize is the size of the AES-GCM authentication tag at the end of a packet.
	TagSize = 16
	// MaxPacket keeps datagrams under a 1500 byte MTU, so they are never fragmented.
	MaxPacket  = 1400
	MaxHostLen = 255

	// Clear header: magic, version, host length, boot ID, instance, nonce counter. The host follows the length.
	headerFixed = 4 + 1 + 1 + 16 + 8 + 8
	// Encrypted part before the body: kind, seq, sent at.
	innerFixed  = 1 + 8 + 8
	recordFixed = 2 + 8 + 8 + 8 + 1 + 1 + 2
	statsSize   = 7*8 + 4

	// MaxAckRanges bounds the missing ranges in one ack, so it fits one packet even with the longest host.
	MaxAckRanges = 64
	// LegacyAckRanges is the limit of agents older than WideAcksSince, which refuse longer acks.
	LegacyAckRanges = 32
	// WideAcksSince is the first agent version that reads MaxAckRanges ranges.
	WideAcksSince = "v0.1.6"
	// MaxAgentVersion bounds the agent version in a heartbeat.
	MaxAgentVersion = 64
)

// Kind tells what a packet carries.
type Kind uint8

const (
	KindKmsg      Kind = 1
	KindPstore    Kind = 2
	KindHeartbeat Kind = 3
	// KindAck goes from the server to the agent and answers a heartbeat.
	KindAck Kind = 4
)

func (k Kind) String() string {
	switch k {
	case KindKmsg:
		return "kmsg"
	case KindPstore:
		return "pstore"
	case KindHeartbeat:
		return "heartbeat"
	case KindAck:
		return "ack"
	}
	return fmt.Sprintf("kind(%d)", k)
}

var (
	ErrMalformed   = errors.New("wire: malformed packet")
	ErrVersion     = errors.New("wire: unsupported version")
	ErrUnknownHost = errors.New("wire: no key for host")
	ErrAuth        = errors.New("wire: authentication failed")
	ErrTooLarge    = errors.New("wire: packet too large")
	ErrHost        = errors.New("wire: invalid host name")
	ErrKind        = errors.New("wire: unknown kind")
)

// Packet is one datagram. Seq starts at 1 and grows by one per packet sent by an agent instance.
type Packet struct {
	Version  uint8 // set by Decode and Seal; Seal writes an older version only when asked
	Host     string
	BootID   [16]byte
	Instance uint64
	Seq      uint64
	SentAt   int64 // unix nanoseconds
	Kind     Kind
	Record   Record // for KindKmsg and KindPstore
	Stats    Stats  // for KindHeartbeat
	// Oldest is the lowest seq the agent can still send again, for KindHeartbeat since version 3.
	// Packets below it that never arrived are lost for good.
	Oldest uint64
	// AgentVersion is the build version of the agent, for KindHeartbeat since version 4.
	AgentVersion string
}

// Range is an inclusive range of packet sequence numbers.
type Range struct{ From, To uint64 }

// Ack answers a heartbeat. Since version 3 it also tells which packets the server has.
type Ack struct {
	Seq    uint64 // seq of the heartbeat it answers
	SentAt int64  // SentAt of that heartbeat
	// Every packet up to Upto arrived, except the ranges in Missing. Upto 0 tells nothing.
	Upto    uint64
	Missing []Range
}

// Record is one log line, or one part of a line too long for a single packet.
type Record struct {
	Priority uint16 // facility<<3 | level
	Seq      uint64 // kmsg sequence number, or line number inside a pstore file
	TsUsec   uint64 // microseconds since boot
	FileID   uint64 // pstore file fingerprint, 0 for kmsg
	Part     uint8  // 1-based part index
	Parts    uint8
	Msg      string
}

// Stats are agent counters sent with every heartbeat.
type Stats struct {
	KmsgRead      uint64
	KmsgOverruns  uint64 // times the kernel overwrote records before they were read
	KmsgInvalid   uint64
	BufferDrops   uint64 // records dropped because the in-memory buffer was full
	SendErrors    uint64
	PstoreRecords uint64
	UptimeSec     uint64
	Buffered      uint32
}

// MaxMsg returns the largest message that fits in one record packet for the given host.
// It uses the version 5 header, the larger one, so a record fits every version.
func MaxMsg(hostLen int) int {
	return MaxPacket - TagSize - headerFS - hostLen - innerFixed - recordFixed
}

// runAEAD derives the AES-256-GCM cipher of one agent run, so each run has its own key.
func runAEAD(key []byte, bootID [16]byte, instance uint64) (cipher.AEAD, error) {
	return deriveAEAD(key, "lastgasp v2 ", bootID, instance)
}

// ackAEAD derives the cipher for acks. A key of its own keeps server nonces apart from agent nonces.
func ackAEAD(key []byte, bootID [16]byte, instance uint64) (cipher.AEAD, error) {
	return deriveAEAD(key, "lastgasp v2 ack ", bootID, instance)
}

func deriveAEAD(key []byte, label string, bootID [16]byte, instance uint64) (cipher.AEAD, error) {
	info := make([]byte, 0, 40)
	info = append(info, label...)
	info = append(info, bootID[:]...)
	info = binary.BigEndian.AppendUint64(info, instance)
	sub, err := hkdf.Key(sha256.New, key, nil, string(info), 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func nonce(counter uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n[:]
}

// Sealer encrypts the packets of one agent run. Every packet uses a new nonce from a counter.
type Sealer struct {
	host     string
	bootID   [16]byte
	instance uint64
	aead     cipher.AEAD
	counter  atomic.Uint64
}

// ValidHost reports whether host can be used as a name: valid UTF-8, at most MaxHostLen bytes,
// and no spaces or control characters, as it ends up in metric labels and the web UI.
func ValidHost(host string) bool {
	if host == "" || len(host) > MaxHostLen || !utf8.ValidString(host) {
		return false
	}
	for _, r := range host {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// NewSealer prepares encryption for one agent run.
func NewSealer(key []byte, host string, bootID [16]byte, instance uint64) (*Sealer, error) {
	if !ValidHost(host) {
		return nil, ErrHost
	}
	a, err := runAEAD(key, bootID, instance)
	if err != nil {
		return nil, err
	}
	return &Sealer{host: host, bootID: bootID, instance: instance, aead: a}, nil
}

// Seal encodes and encrypts p. Host, BootID and Instance are taken from the sealer.
func (s *Sealer) Seal(p *Packet) ([]byte, error) {
	p.Host, p.BootID, p.Instance = s.host, s.bootID, s.instance
	if p.Version < minVersion || p.Version > version {
		p.Version = version
	}
	inner, err := encodeInner(p, p.Version)
	if err != nil {
		return nil, err
	}
	if headerFixed+len(s.host)+len(inner)+TagSize > MaxPacket {
		return nil, ErrTooLarge
	}
	ctr := s.counter.Add(1)
	b := header(p.Version, s.host, s.bootID, s.instance, ctr)
	// The clear header is authenticated as additional data.
	return s.aead.Seal(b, nonce(ctr), inner, b), nil
}

func header(ver uint8, host string, bootID [16]byte, instance, ctr uint64) []byte {
	b := make([]byte, 0, MaxPacket)
	b = append(b, magic...)
	b = append(b, ver, byte(len(host)))
	b = append(b, host...)
	b = append(b, bootID[:]...)
	b = binary.BigEndian.AppendUint64(b, instance)
	return binary.BigEndian.AppendUint64(b, ctr)
}

// AckRanges returns how many missing ranges an ack to an agent of this version may hold.
// Development builds and versions that cannot be parsed get the legacy limit.
func AckRanges(agentVersion string) int {
	have, ok := parseVersion(agentVersion)
	want, _ := parseVersion(WideAcksSince)
	if !ok {
		return LegacyAckRanges
	}
	for i := range have {
		if have[i] != want[i] {
			if have[i] > want[i] {
				return MaxAckRanges
			}
			return LegacyAckRanges
		}
	}
	return MaxAckRanges
}

// parseVersion reads "vX.Y.Z", ignoring anything after the patch number such as "-rc1".
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v, ok := strings.CutPrefix(v, "v")
	if !ok {
		return out, false
	}
	for i := range out {
		n := 0
		digits := 0
		for digits < len(v) && v[digits] >= '0' && v[digits] <= '9' && digits < 9 {
			n = n*10 + int(v[digits]-'0')
			digits++
		}
		if digits == 0 {
			return out, false
		}
		out[i], v = n, v[digits:]
		if i < 2 {
			if v, ok = strings.CutPrefix(v, "."); !ok {
				return out, false
			}
		}
	}
	return out, true
}

// EncodeAck builds the server answer to the heartbeat p, sealed with the key of p's host.
// upto and missing tell what the server received. A version 2 heartbeat gets a version 2 ack without them.
func EncodeAck(p *Packet, upto uint64, missing []Range, key []byte) ([]byte, error) {
	if len(missing) > MaxAckRanges {
		return nil, ErrTooLarge
	}
	a, err := ackAEAD(key, p.BootID, p.Instance)
	if err != nil {
		return nil, err
	}
	var r [8]byte
	rand.Read(r[:])
	ctr := binary.BigEndian.Uint64(r[:])
	// The ack has the version of the heartbeat, so an older agent can read it.
	ver := min(max(p.Version, minVersion), version)
	b := encodeAck(p, ver, upto, missing)
	h := header(ver, p.Host, p.BootID, p.Instance, ctr)
	return a.Seal(h, nonce(ctr), b, h), nil
}

func encodeAck(p *Packet, ver uint8, upto uint64, missing []Range) []byte {
	b := make([]byte, 0, MaxPacket)
	b = append(b, byte(KindAck))
	b = binary.BigEndian.AppendUint64(b, p.Seq)
	b = binary.BigEndian.AppendUint64(b, uint64(p.SentAt))
	if ver >= 3 {
		b = binary.BigEndian.AppendUint64(b, upto)
		b = append(b, byte(len(missing)))
		for _, m := range missing {
			b = binary.BigEndian.AppendUint64(b, m.From)
			b = binary.BigEndian.AppendUint64(b, m.To)
		}
	}
	return b
}

// DecodeAck checks an ack sent to the agent run (host, bootID, instance). The returned ack holds the seq and
// SentAt of the heartbeat it answers, so the agent can refuse answers to old heartbeats.
func DecodeAck(buf, key []byte, host string, bootID [16]byte, instance uint64) (Ack, error) {
	var ack Ack
	h, err := parseHeader(buf)
	if err != nil {
		return ack, err
	}
	if h.host != host || h.bootID != bootID || h.instance != instance {
		return ack, ErrAuth
	}
	a, err := ackAEAD(key, bootID, instance)
	if err != nil {
		return ack, err
	}
	inner, err := a.Open(nil, nonce(h.ctr), buf[h.len:], buf[:h.len])
	if err != nil {
		return ack, ErrAuth
	}
	return decodeAck(inner, h.version)
}

func decodeAck(inner []byte, ver uint8) (Ack, error) {
	var ack Ack
	r := reader{b: inner}
	kind := Kind(r.u8())
	ack.Seq, ack.SentAt = r.u64(), int64(r.u64())
	if ver >= 3 {
		ack.Upto = r.u64()
		n := int(r.u8())
		if n > MaxAckRanges {
			return Ack{}, ErrMalformed
		}
		for i := 0; i < n && !r.bad; i++ {
			m := Range{From: r.u64(), To: r.u64()}
			// Ranges must be in order and below Upto, so the agent can trust them blindly.
			if m.From > m.To || m.To > ack.Upto || (i > 0 && m.From <= ack.Missing[i-1].To) {
				return Ack{}, ErrMalformed
			}
			ack.Missing = append(ack.Missing, m)
		}
	}
	if r.bad || len(r.b) != 0 || kind != KindAck {
		return Ack{}, ErrMalformed
	}
	return ack, nil
}

// Encode encrypts a single packet with a random nonce counter. Agents use a Sealer instead.
func Encode(p *Packet, key []byte) ([]byte, error) {
	s, err := NewSealer(key, p.Host, p.BootID, p.Instance)
	if err != nil {
		return nil, err
	}
	var r [8]byte
	rand.Read(r[:])
	s.counter.Store(binary.BigEndian.Uint64(r[:]) >> 1)
	return s.Seal(p)
}

func encodeInner(p *Packet, ver uint8) ([]byte, error) {
	b := make([]byte, 0, MaxPacket)
	b = append(b, byte(p.Kind))
	b = binary.BigEndian.AppendUint64(b, p.Seq)
	b = binary.BigEndian.AppendUint64(b, uint64(p.SentAt))
	switch p.Kind {
	case KindKmsg, KindPstore:
		r := &p.Record
		if len(r.Msg) > MaxPacket {
			return nil, ErrTooLarge
		}
		b = binary.BigEndian.AppendUint16(b, r.Priority)
		b = binary.BigEndian.AppendUint64(b, r.Seq)
		b = binary.BigEndian.AppendUint64(b, r.TsUsec)
		b = binary.BigEndian.AppendUint64(b, r.FileID)
		b = append(b, r.Part, r.Parts)
		b = binary.BigEndian.AppendUint16(b, uint16(len(r.Msg)))
		b = append(b, r.Msg...)
	case KindHeartbeat:
		s := &p.Stats
		for _, v := range []uint64{s.KmsgRead, s.KmsgOverruns, s.KmsgInvalid, s.BufferDrops, s.SendErrors, s.PstoreRecords, s.UptimeSec} {
			b = binary.BigEndian.AppendUint64(b, v)
		}
		b = binary.BigEndian.AppendUint32(b, s.Buffered)
		if ver >= 3 {
			b = binary.BigEndian.AppendUint64(b, p.Oldest)
		}
		if ver >= 4 {
			v := p.AgentVersion
			if len(v) > MaxAgentVersion {
				v = v[:MaxAgentVersion]
			}
			b = append(b, byte(len(v)))
			b = append(b, v...)
		}
	default:
		return nil, ErrKind
	}
	return b, nil
}

type clearHeader struct {
	version  uint8
	host     string
	bootID   [16]byte
	instance uint64
	ctr      uint64
	len      int
}

func parseHeader(buf []byte) (clearHeader, error) {
	var h clearHeader
	if len(buf) < 6 || string(buf[:4]) != magic {
		return h, ErrMalformed
	}
	if buf[4] < minVersion || buf[4] > version {
		return h, ErrVersion
	}
	h.version = buf[4]
	hostLen := int(buf[5])
	h.len = headerFixed + hostLen
	if hostLen == 0 || len(buf) < h.len+innerFixed+TagSize {
		return h, ErrMalformed
	}
	h.host = string(buf[6 : 6+hostLen])
	if !ValidHost(h.host) {
		return h, ErrHost
	}
	hr := reader{b: buf[6+hostLen : h.len]}
	copy(h.bootID[:], hr.take(16))
	h.instance = hr.u64()
	h.ctr = hr.u64()
	return h, nil
}

// Decode looks up the key with keyFor, checks and decrypts the packet, and parses it.
func Decode(buf []byte, keyFor func(host string) []byte) (*Packet, error) {
	h, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}
	key := keyFor(h.host)
	if key == nil {
		return nil, ErrUnknownHost
	}
	p := &Packet{Version: h.version, Host: h.host, BootID: h.bootID, Instance: h.instance}
	a, err := runAEAD(key, p.BootID, p.Instance)
	if err != nil {
		return nil, err
	}
	inner, err := a.Open(nil, nonce(h.ctr), buf[h.len:], buf[:h.len])
	if err != nil {
		return nil, ErrAuth
	}
	if err := decodeInner(p, inner); err != nil {
		return nil, err
	}
	return p, nil
}

// decodeInner parses the encrypted part of a packet into p. p.Version must be set.
func decodeInner(p *Packet, inner []byte) error {
	r := reader{b: inner}
	p.Kind = Kind(r.u8())
	p.Seq = r.u64()
	p.SentAt = int64(r.u64())
	switch p.Kind {
	case KindKmsg, KindPstore:
		rec := &p.Record
		rec.Priority = r.u16()
		rec.Seq = r.u64()
		rec.TsUsec = r.u64()
		rec.FileID = r.u64()
		rec.Part = r.u8()
		rec.Parts = r.u8()
		rec.Msg = string(r.take(int(r.u16())))
	case KindHeartbeat:
		s := &p.Stats
		for _, v := range []*uint64{&s.KmsgRead, &s.KmsgOverruns, &s.KmsgInvalid, &s.BufferDrops, &s.SendErrors, &s.PstoreRecords, &s.UptimeSec} {
			*v = r.u64()
		}
		s.Buffered = r.u32()
		if p.Version >= 3 {
			p.Oldest = r.u64()
		}
		if p.Version >= 4 {
			n := int(r.u8())
			if n > MaxAgentVersion {
				return ErrMalformed
			}
			p.AgentVersion = strings.ToValidUTF8(string(r.take(n)), "?")
		}
	default:
		return ErrKind
	}
	if r.bad || len(r.b) != 0 {
		return ErrMalformed
	}
	return nil
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || len(r.b) < n {
		r.bad = true
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8   { return r.take(1)[0] }
func (r *reader) u16() uint16 { return binary.BigEndian.Uint16(r.take(2)) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }

// SplitMessage cuts msg into chunks of at most max bytes, avoiding cuts inside a UTF-8 character.
func SplitMessage(msg string, max int) []string {
	if len(msg) <= max {
		return []string{msg}
	}
	var parts []string
	for len(msg) > max {
		cut := max
		for i := 0; i < utf8.UTFMax && cut-i > 0; i++ {
			if utf8.RuneStart(msg[cut-i]) {
				cut -= i
				break
			}
		}
		parts = append(parts, msg[:cut])
		msg = msg[cut:]
	}
	return append(parts, msg)
}

// ParseKey decodes a hex key. Keys shorter than 16 bytes are rejected.
func ParseKey(s string) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("key is not valid hex: %w", err)
	}
	if len(k) < 16 {
		return nil, errors.New("key must be at least 16 bytes (32 hex characters)")
	}
	return k, nil
}

// ParseBootID parses the UUID found in /proc/sys/kernel/random/boot_id.
func ParseBootID(s string) ([16]byte, error) {
	var id [16]byte
	h := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(h) != 32 {
		return id, ErrMalformed
	}
	if _, err := hex.Decode(id[:], []byte(h)); err != nil {
		return id, err
	}
	return id, nil
}

// FormatBootID prints a boot ID in the same form the kernel uses.
func FormatBootID(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
