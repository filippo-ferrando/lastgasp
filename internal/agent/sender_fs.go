package agent

import (
	"errors"
	"net"
	"time"

	"lastgasp/internal/wire"
)

// peer is the version 5 state of one server address: its sessions and the handshakes on the way.
type peer struct {
	addr      *net.UDPAddr
	cur, prev *wire.Session
	curAt     time.Time // when cur was made
	pending   []*wire.Handshake
	lastInit  time.Time
	lastAck   time.Time
}

// maxPending bounds the handshakes waiting for a reply from one server.
const maxPending = 4

// rejectMargin stops using a session a bit before the server refuses it, as the server made it a round trip earlier.
const rejectMargin = 5 * time.Second

var errNoSession = errors.New("no session with any server yet")

// fs reports whether the sender uses version 5 sessions. They need acks, as the handshake needs a reply.
func (s *Sender) fs() bool { return s.ForwardSecrecy && s.WaitAck && s.Heartbeat > 0 }

func (s *Sender) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// usable reports whether the current session may still carry data.
func (p *peer) usable(now time.Time) bool {
	return p.cur != nil && now.Sub(p.curAt) < wire.RejectAfter-rejectMargin
}

func (s *Sender) peerReady(p *peer, now time.Time) bool {
	return p.usable(now) && now.Sub(p.lastAck) < ackWindow*s.Heartbeat
}

func (s *Sender) readyFS() bool {
	now := s.now()
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	for _, p := range s.peers {
		if s.peerReady(p, now) {
			return true
		}
	}
	return false
}

type datagram struct {
	b    []byte
	addr *net.UDPAddr
}

// tickPeers follows the server list, drops sessions of servers that stopped answering and sends
// handshake inits where a session is missing or old. It returns the time until it has work again.
func (s *Sender) tickPeers() time.Duration {
	out, next := s.planPeers(s.now(), s.Resolver.Addrs())
	if len(out) > 0 {
		s.writeAll(out)
	}
	return next
}

// planPeers does the work of tickPeers under the lock, which a panic here must not leave held.
func (s *Sender) planPeers(now time.Time, addrs []*net.UDPAddr) ([]datagram, time.Duration) {
	next := time.Duration(1<<63 - 1)
	var out []datagram
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	seen := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		k := a.String()
		seen[k] = true
		p := s.peers[k]
		if p == nil {
			p = &peer{}
			s.peers[k] = p
		}
		p.addr = a
		if p.cur != nil && (!p.usable(now) || now.Sub(p.lastAck) >= ackWindow*s.Heartbeat) {
			// The server lost the session (a restart) or it is too old: start over.
			p.cur, p.prev = nil, nil
		}
		if p.cur != nil && now.Sub(p.curAt) < wire.RekeyAfter {
			next = min(next, wire.RekeyAfter-now.Sub(p.curAt), ackWindow*s.Heartbeat-now.Sub(p.lastAck))
			continue
		}
		if wait := wire.HandshakeRetry - now.Sub(p.lastInit); !p.lastInit.IsZero() && wait > 0 {
			next = min(next, wait)
			continue
		}
		s.hsNum++
		hs, b, err := wire.StartHandshake(s.Key, s.Host, s.BootID, s.Instance, s.hsNum)
		if err != nil {
			// Host and key are checked at start, so this only happens on a bug.
			s.Log.Printf("send: handshake: %v", err)
			continue
		}
		if len(p.pending) >= maxPending {
			p.pending = p.pending[1:]
		}
		p.pending = append(p.pending, hs)
		p.lastInit = now
		next = min(next, wire.HandshakeRetry)
		out = append(out, datagram{b, a})
	}
	for k := range s.peers {
		if !seen[k] {
			delete(s.peers, k)
		}
	}
	return out, next
}

// sealFS seals p once for every server with a session.
func (s *Sender) sealFS(p *wire.Packet) ([]datagram, error) {
	now := s.now()
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	var out []datagram
	for _, pr := range s.peers {
		if !pr.usable(now) {
			continue
		}
		b, err := pr.cur.Seal(p)
		if err != nil {
			return nil, err
		}
		out = append(out, datagram{b, pr.addr})
	}
	if len(out) == 0 {
		return nil, errNoSession
	}
	return out, nil
}

// readReplyFS handles a handshake reply or an ack from a server. It returns the ack, if it is one,
// and the peer it came from. A finished handshake counts as an ack, as it proves the server listens.
func (s *Sender) readReplyFS(buf []byte) (*wire.Ack, *peer) {
	h, err := wire.ParseHeader(buf)
	if err != nil {
		return nil, nil
	}
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	for _, p := range s.peers {
		switch h.Type {
		case wire.TypeReply:
			for _, hs := range p.pending {
				if hs.Session() != h.Session {
					continue
				}
				sess, err := hs.Finish(buf)
				if err != nil {
					return nil, nil
				}
				now := s.now()
				// The old session stays for acks still on the way.
				p.prev, p.cur, p.curAt, p.lastAck = p.cur, sess, now, now
				p.pending = nil
				return nil, p
			}
		case wire.TypeAck:
			for _, sess := range []*wire.Session{p.cur, p.prev} {
				if sess == nil || sess.ID != h.Session {
					continue
				}
				ack, err := sess.OpenAck(buf)
				if err != nil {
					return nil, nil
				}
				return &ack, p
			}
		}
	}
	return nil, nil
}

func (s *Sender) peerAcked(p *peer) {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	p.lastAck = s.now()
}
