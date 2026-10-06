package agent

import (
	"context"
	"errors"
	"net"
	"time"

	"lastgasp/internal/wire"
)

type packetConn interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	Close() error
}

// Sender encrypts queued records and sends each one to every server.
type Sender struct {
	Host      string
	BootID    [16]byte
	Instance  uint64
	Key       []byte
	Queue     *Queue
	Pstore    *Queue // sent before Queue, may be nil
	Resolver  interface{ Addrs() []*net.UDPAddr }
	Stats     *Stats
	Log       *Logger
	Rate      int           // max packets per second, 0 means no limit
	Heartbeat time.Duration // interval between heartbeats

	newConn func() (packetConn, error)
	conn    packetConn
	sealer  *wire.Sealer
	seq     uint64
	start   time.Time
	pace    pacer
}

var errNoAddr = errors.New("no server address known yet")

func (s *Sender) init() error {
	sealer, err := wire.NewSealer(s.Key, s.Host, s.BootID, s.Instance)
	if err != nil {
		return err
	}
	s.sealer = sealer
	if s.newConn == nil {
		s.newConn = func() (packetConn, error) { return net.ListenUDP("udp", nil) }
	}
	if s.start.IsZero() {
		s.start = time.Now()
	}
	if s.Rate > 0 {
		s.pace.interval = time.Second / time.Duration(s.Rate)
	}
	return nil
}

// Run sends until ctx is done. A record leaves the queue only after at least one server accepted it.
func (s *Sender) Run(ctx context.Context) {
	if err := s.init(); err != nil {
		// Host and key are checked at start, so this only happens on a bug.
		s.Log.Printf("send: %v", err)
		<-ctx.Done()
		return
	}
	retry := newBackoff(50*time.Millisecond, 2*time.Second)
	nextBeat := time.Now()
	for ctx.Err() == nil {
		if s.Heartbeat > 0 && !time.Now().Before(nextBeat) {
			// A failed heartbeat is not retried: the next one carries newer counters.
			s.send(&wire.Packet{Kind: wire.KindHeartbeat, Stats: s.Stats.snapshot(s.buffered(), time.Since(s.start))})
			nextBeat = time.Now().Add(s.Heartbeat)
		}
		q := s.Queue
		it, ok := Item{}, false
		if s.Pstore != nil {
			it, ok = s.Pstore.Peek()
			q = s.Pstore
		}
		if !ok {
			q = s.Queue
			it, ok = q.Peek()
		}
		if !ok {
			s.wait(ctx, time.Until(nextBeat))
			continue
		}
		err := s.send(&wire.Packet{Kind: it.Kind, Record: it.Rec})
		switch {
		case err == nil:
			retry.Reset()
			q.Done(it)
			s.pace.wait(ctx)
		case errors.Is(err, wire.ErrTooLarge), errors.Is(err, wire.ErrHost), errors.Is(err, wire.ErrKind):
			// This record can never be sent, so drop it instead of blocking the queue forever.
			s.Log.Printf("send: dropping record: %v", err)
			s.Stats.BufferDrops.Add(1)
			q.Done(it)
		default:
			retry.Sleep(ctx)
		}
	}
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *Sender) buffered() int {
	n := s.Queue.Len()
	if s.Pstore != nil {
		n += s.Pstore.Len()
	}
	return n
}

func (s *Sender) wait(ctx context.Context, d time.Duration) {
	if s.Heartbeat <= 0 {
		d = time.Minute
	}
	t := time.NewTimer(max(d, time.Millisecond))
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-s.Queue.Ready():
	case <-t.C:
	}
}

// send uses the next sequence number and keeps it only if one server got the packet,
// so local network errors do not show up as lost packets on the server.
func (s *Sender) send(p *wire.Packet) error {
	p.Seq = s.seq + 1
	p.SentAt = time.Now().UnixNano()
	b, err := s.sealer.Seal(p)
	if err != nil {
		return err
	}
	addrs := s.Resolver.Addrs()
	if len(addrs) == 0 {
		s.Stats.SendErrors.Add(1)
		return errNoAddr
	}
	if s.conn == nil {
		c, err := s.newConn()
		if err != nil {
			s.Stats.SendErrors.Add(1)
			return err
		}
		s.conn = c
	}
	sent := false
	var lastErr error
	for _, a := range addrs {
		if _, err := s.conn.WriteTo(b, a); err != nil {
			lastErr = err
			s.Stats.SendErrors.Add(1)
			continue
		}
		sent = true
	}
	if !sent {
		// A fresh socket helps after interface or address changes.
		s.conn.Close()
		s.conn = nil
		return lastErr
	}
	s.seq = p.Seq
	return nil
}

// pacer spaces packets out so a burst (like the kernel buffer replay at start) does not overflow the server.
type pacer struct {
	interval time.Duration
	next     time.Time
}

func (p *pacer) wait(ctx context.Context) {
	if p.interval == 0 {
		return
	}
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	p.next = p.next.Add(p.interval)
	if d := p.next.Sub(now); d > time.Millisecond {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
		t.Stop()
	}
}
