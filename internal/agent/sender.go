package agent

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"lastgasp/internal/wire"
)

type packetConn interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
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
	// WaitAck holds records until a server answers a heartbeat, so nothing is sent while no server listens.
	WaitAck bool

	newConn func() (packetConn, error)
	conn    packetConn
	sealer  *wire.Sealer
	seq     uint64
	start   time.Time
	pace    pacer
	lastAck atomic.Int64 // time since start of the newest valid ack, monotonic so clock steps at boot do not matter
	acked   chan struct{}
	state   string // "", "holding" or "sending", to log only changes

	beatMu sync.Mutex
	beats  [16]int64 // SentAt of the newest heartbeats, an ack must answer one of them
	nbeat  int
}

// ackWindow is how long the agent keeps sending after the newest ack, in heartbeats.
const ackWindow = 3

var errNoAddr = errors.New("no server address known yet")

func (s *Sender) init() error {
	// After a panic Run starts again. The sealer is kept, as a new one would use the same nonces again.
	if s.sealer != nil {
		return nil
	}
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
	s.acked = make(chan struct{}, 1)
	return nil
}

// ready reports whether records may be sent: acks are not used, or one arrived within three heartbeats.
func (s *Sender) ready() bool {
	if !s.WaitAck || s.Heartbeat <= 0 {
		return true
	}
	last := s.lastAck.Load()
	return last != 0 && time.Since(s.start)-time.Duration(last) < ackWindow*s.Heartbeat
}

func (s *Sender) logState(ready bool) {
	if !s.WaitAck || s.Heartbeat <= 0 {
		return
	}
	switch {
	case ready && s.state != "sending":
		s.Log.Printf("send: a server answered, sending %d buffered records", s.buffered())
		s.state = "sending"
	case !ready && s.state == "":
		s.Log.Printf("send: waiting for a server to answer before sending records")
		s.state = "holding"
	case !ready && s.state == "sending":
		s.Log.Printf("send: no answer from any server for %s, holding records", ackWindow*s.Heartbeat)
		s.state = "holding"
	}
}

func (s *Sender) noteBeat(sentAt int64) {
	s.beatMu.Lock()
	s.beats[s.nbeat%len(s.beats)] = sentAt
	s.nbeat++
	s.beatMu.Unlock()
}

// recentBeat reports whether sentAt belongs to one of the newest heartbeats, so a replayed old ack is refused.
func (s *Sender) recentBeat(sentAt int64) bool {
	s.beatMu.Lock()
	defer s.beatMu.Unlock()
	for _, b := range s.beats {
		if b != 0 && b == sentAt {
			return true
		}
	}
	return false
}

// readAcks reads server answers until c is closed.
func (s *Sender) readAcks(c packetConn) {
	buf := make([]byte, wire.MaxPacket)
	for {
		n, _, err := c.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		_, sentAt, err := wire.DecodeAck(buf[:n], s.Key, s.Host, s.BootID, s.Instance)
		if err != nil || !s.recentBeat(sentAt) {
			continue
		}
		s.lastAck.Store(int64(time.Since(s.start)) + 1)
		select {
		case s.acked <- struct{}{}:
		default:
		}
	}
}

// Run sends until ctx is done, then tries to send what is left for drainTime. A record leaves the
// queue once the socket took it for at least one server. UDP gives no delivery receipt, acks only tell that a server listens.
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
		ready := s.ready()
		s.logState(ready)
		if s.Heartbeat > 0 && !time.Now().Before(nextBeat) {
			// A failed heartbeat is not retried: the next one carries newer counters.
			beat := &wire.Packet{Kind: wire.KindHeartbeat, Stats: s.Stats.snapshot(s.buffered(), time.Since(s.start))}
			if ready {
				s.send(beat)
				nextBeat = time.Now().Add(s.Heartbeat)
			} else {
				// A probe has seq 0, so probes nobody received do not count as missing packets.
				s.write(beat)
				nextBeat = time.Now().Add(min(time.Second, s.Heartbeat))
			}
			s.noteBeat(beat.SentAt)
		}
		if !ready {
			s.wait(ctx, time.Until(nextBeat), false)
			continue
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
			s.wait(ctx, time.Until(nextBeat), true)
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
	s.drain()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// drainTime bounds the last sends on shutdown, so lines logged while the machine goes down still get out.
const drainTime = 2 * time.Second

func (s *Sender) drain() {
	if !s.ready() {
		return
	}
	deadline := time.Now().Add(drainTime)
	for time.Now().Before(deadline) {
		q := s.Queue
		it, ok := Item{}, false
		if s.Pstore != nil {
			q = s.Pstore
			it, ok = q.Peek()
		}
		if !ok {
			q = s.Queue
			if it, ok = q.Peek(); !ok {
				return
			}
		}
		if err := s.send(&wire.Packet{Kind: it.Kind, Record: it.Rec}); err != nil {
			return
		}
		q.Done(it)
	}
}

func (s *Sender) buffered() int {
	n := s.Queue.Len()
	if s.Pstore != nil {
		n += s.Pstore.Len()
	}
	return n
}

// wait sleeps for d, or until an ack arrives, or until a record is queued when queue is true.
func (s *Sender) wait(ctx context.Context, d time.Duration, queue bool) {
	if s.Heartbeat <= 0 {
		d = time.Minute
	}
	t := time.NewTimer(max(d, time.Millisecond))
	defer t.Stop()
	var pushed <-chan struct{}
	if queue {
		pushed = s.Queue.Ready()
	}
	select {
	case <-ctx.Done():
	case <-pushed:
	case <-s.acked:
	case <-t.C:
	}
}

// send uses the next sequence number and keeps it only if one server got the packet,
// so local network errors do not show up as lost packets on the server.
func (s *Sender) send(p *wire.Packet) error {
	p.Seq = s.seq + 1
	if err := s.write(p); err != nil {
		return err
	}
	s.seq = p.Seq
	return nil
}

// write seals p and sends it to every server. It succeeds if at least one write worked.
func (s *Sender) write(p *wire.Packet) error {
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
		if s.WaitAck {
			go s.readAcks(c)
		}
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
