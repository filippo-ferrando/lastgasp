package agent

import (
	"context"
	"errors"
	"net"
	"os"
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
	First     *Queue // pstore lines and records of the previous run, sent before Queue, may be nil
	Journal   *Queue // userspace lines, sent after Queue, may be nil
	Resolver  interface{ Addrs() []*net.UDPAddr }
	Stats     *Stats
	Log       *Logger
	Rate      int           // max packets per second, 0 means no limit
	Heartbeat time.Duration // interval between heartbeats
	// WaitAck holds records until a server answers a heartbeat, so nothing is sent while no server listens.
	WaitAck bool
	// ForwardSecrecy uses version 5 sessions with a Noise handshake per server. It needs WaitAck.
	ForwardSecrecy bool
	Version        string // agent version sent in heartbeats
	// PmsgPath gets the kmsg records still unconfirmed when Run stops, up to PmsgMax bytes. Empty to disable.
	PmsgPath string
	PmsgMax  int

	newConn func() (packetConn, error)
	conn    packetConn
	sealer  *wire.Sealer
	seq     uint64
	tx      uint64 // packets written, including probes and records sent again
	start   time.Time
	pace    pacer
	lastAck atomic.Int64 // time since start of the newest valid ack, monotonic so clock steps at boot do not matter
	acked   chan struct{}
	state   string // "", "holding" or "sending", to log only changes

	beatMu sync.Mutex
	beats  [16]beatSent // the newest heartbeats, an ack must answer one of them
	nbeat  int
	// sentBeats holds heartbeats not confirmed yet, to send again the ones a server missed.
	sentBeats beatSeqs

	clock  func() time.Time // for tests, nil is time.Now
	peerMu sync.Mutex
	peers  map[string]*peer // version 5 state per server address
	hsNum  uint64           // handshakes started, grows for every one
}

type beatSent struct {
	sentAt int64
	tx     uint64
}

// ackWindow is how long the agent keeps sending after the newest ack, in heartbeats.
const ackWindow = 3

// earlyBeat is the shortest gap between heartbeats sent early to get records confirmed. The server
// answers at most every 200ms.
const earlyBeat = 250 * time.Millisecond

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
	s.peers = map[string]*peer{}
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
	if s.fs() {
		return s.readyFS()
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
	case !ready && s.state == "" && s.fs():
		s.Log.Printf("send: waiting for a server to answer a handshake before sending records " +
			"(servers that do not know packet version 5 never answer, see -forward-secrecy)")
		s.state = "holding"
	case !ready && s.state == "":
		s.Log.Printf("send: waiting for a server to answer before sending records")
		s.state = "holding"
	case !ready && s.state == "sending":
		s.Log.Printf("send: no answer from any server for %s, holding records", ackWindow*s.Heartbeat)
		s.state = "holding"
	}
}

func (s *Sender) noteBeat(sentAt int64, tx uint64) {
	s.beatMu.Lock()
	s.beats[s.nbeat%len(s.beats)] = beatSent{sentAt, tx}
	s.nbeat++
	s.beatMu.Unlock()
}

// recentBeat finds the transmission of one of the newest heartbeats by its SentAt, so a replayed old ack is refused.
func (s *Sender) recentBeat(sentAt int64) (tx uint64, ok bool) {
	s.beatMu.Lock()
	defer s.beatMu.Unlock()
	for _, b := range s.beats {
		if b.sentAt != 0 && b.sentAt == sentAt {
			return b.tx, true
		}
	}
	return 0, false
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
		var ack wire.Ack
		var from *peer
		if s.fs() {
			a, p := s.readReplyFS(buf[:n])
			if p == nil {
				continue
			}
			if a == nil {
				// A finished handshake: the server listens, records can go.
				s.notifyAck()
				continue
			}
			ack, from = *a, p
		} else if ack, err = wire.DecodeAck(buf[:n], s.Key, s.Host, s.BootID, s.Instance); err != nil {
			continue
		}
		tx, ok := s.recentBeat(ack.SentAt)
		if !ok {
			continue
		}
		if from != nil {
			s.peerAcked(from)
		}
		if ack.Upto > 0 {
			for _, q := range s.queues() {
				q.Ack(ack.Upto, ack.Missing, tx)
			}
			s.sentBeats.ack(ack.Upto, ack.Missing, tx)
		}
		s.notifyAck()
	}
}

func (s *Sender) notifyAck() {
	s.lastAck.Store(int64(time.Since(s.start)) + 1)
	select {
	case s.acked <- struct{}{}:
	default:
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
	nextBeat, lastBeat := time.Now(), time.Time{}
	for ctx.Err() == nil {
		// Time until the next handshake init, for version 5 only.
		initWait := time.Duration(1<<63 - 1)
		if s.fs() {
			initWait = s.tickPeers()
		}
		ready := s.ready()
		s.logState(ready)
		if s.Heartbeat > 0 && (!time.Now().Before(nextBeat) || (ready && s.needConfirm() && time.Since(lastBeat) >= earlyBeat)) {
			// A failed heartbeat is not retried: the next one carries newer counters.
			beat := &wire.Packet{Kind: wire.KindHeartbeat, Stats: s.Stats.snapshot(s.buffered(), time.Since(s.start)), Oldest: s.oldest(),
				AgentVersion: s.Version}
			switch {
			case ready:
				if s.send(beat) == nil && s.WaitAck {
					s.sentBeats.add(beat.Seq, s.tx)
				}
				nextBeat = time.Now().Add(s.Heartbeat)
			case !s.fs():
				// A probe has seq 0, so probes nobody received do not count as missing packets.
				s.write(beat)
				nextBeat = time.Now().Add(min(time.Second, s.Heartbeat))
			}
			// With version 5 the handshake init is the probe, and the first heartbeat goes once it is answered.
			if ready || !s.fs() {
				s.noteBeat(beat.SentAt, s.tx)
				lastBeat = time.Now()
			}
		}
		if !ready {
			d := time.Until(nextBeat)
			if s.fs() {
				// No heartbeat is due while holding, only handshakes. The cap also covers servers not resolved yet.
				d = min(initWait, wire.HandshakeRetry)
			}
			s.wait(ctx, d, false)
			continue
		}
		if seq, ok := s.sentBeats.next(); ok {
			if s.resendBeat(seq) == nil {
				s.pace.wait(ctx)
			} else {
				retry.Sleep(ctx)
			}
			continue
		}
		q, it, ok := s.next()
		if !ok {
			wake := time.Until(nextBeat)
			if s.needConfirm() {
				wake = min(wake, time.Until(lastBeat.Add(earlyBeat)))
			}
			s.wait(ctx, min(wake, initWait), true)
			continue
		}
		err := s.sendItem(q, it)
		switch {
		case err == nil:
			retry.Reset()
			s.pace.wait(ctx)
		case errors.Is(err, wire.ErrTooLarge), errors.Is(err, wire.ErrHost), errors.Is(err, wire.ErrKind):
			// This record can never be sent, so drop it instead of blocking the queue forever.
			s.Log.Printf("send: dropping record: %v", err)
			s.Stats.BufferDrops.Add(1)
			q.Drop(it)
		default:
			retry.Sleep(ctx)
		}
	}
	s.drain()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.savePmsg()
}

// savePmsg keeps what no server confirmed in pmsg, also when no server answered at all.
func (s *Sender) savePmsg() {
	if s.PmsgPath == "" || s.PmsgMax <= 0 {
		return
	}
	var items []Item
	if s.First != nil {
		items = s.First.Pending() // older than the kmsg queue, pstore lines in it are skipped
	}
	n, err := SavePmsg(s.PmsgPath, append(items, s.Queue.Pending()...), s.PmsgMax)
	switch {
	case err != nil && os.IsNotExist(err):
		// The kernel has no pmsg (no ramoops with pmsg_size), which is common.
	case err != nil:
		s.Log.Printf("pmsg: saved %d records: %v", n, err)
	case n > 0:
		s.Log.Printf("pmsg: saved %d unconfirmed records for the next boot", n)
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
		q, it, ok := s.next()
		if !ok {
			return
		}
		if err := s.sendItem(q, it); err != nil {
			return
		}
	}
}

// queues returns the queues in send order: First, the kmsg queue, then Journal.
func (s *Sender) queues() []*Queue {
	out := make([]*Queue, 0, 3)
	for _, q := range []*Queue{s.First, s.Queue, s.Journal} {
		if q != nil {
			out = append(out, q)
		}
	}
	return out
}

// next picks the next record to send, in the order of queues, so kernel lines never wait for userspace ones.
func (s *Sender) next() (*Queue, Item, bool) {
	for _, q := range s.queues() {
		if it, ok := q.Next(); ok {
			return q, it, true
		}
	}
	return nil, Item{}, false
}

// sendItem sends a record, or sends it again with its first seq, so the server sees a late packet.
func (s *Sender) sendItem(q *Queue, it Item) error {
	p := &wire.Packet{Kind: it.Kind, Record: it.Rec}
	var err error
	if it.seq != 0 {
		p.Seq = it.seq
		err = s.write(p)
	} else {
		err = s.send(p)
	}
	if err == nil {
		// Without acks nothing would ever confirm the record, so it is done once sent.
		q.Sent(it, p.Seq, s.tx, s.WaitAck)
	}
	return err
}

// resendBeat sends a heartbeat again with the seq of one a server missed, with fresh counters.
func (s *Sender) resendBeat(seq uint64) error {
	beat := &wire.Packet{Kind: wire.KindHeartbeat, Seq: seq, Stats: s.Stats.snapshot(s.buffered(), time.Since(s.start)),
		Oldest: s.oldest(), AgentVersion: s.Version}
	if err := s.write(beat); err != nil {
		return err
	}
	s.sentBeats.resent(seq, s.tx)
	s.noteBeat(beat.SentAt, s.tx)
	return nil
}

// oldest returns the lowest seq the agent can still send again. Packets below it are never sent again.
func (s *Sender) oldest() uint64 {
	o := s.seq + 1
	if v := s.sentBeats.oldest(); v != 0 && v < o {
		o = v
	}
	for _, q := range s.queues() {
		if v := q.Oldest(); v != 0 && v < o {
			o = v
		}
	}
	return o
}

// needConfirm reports whether half the buffer waits for a server to confirm it, so a heartbeat should go now.
func (s *Sender) needConfirm() bool {
	return s.WaitAck && s.Queue.Unconfirmed() >= max(1, s.Queue.Cap()/2)
}

func (s *Sender) buffered() int {
	n := 0
	for _, q := range s.queues() {
		n += q.Len()
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
	var pushed, journal <-chan struct{}
	if queue {
		pushed = s.Queue.Ready()
		if s.Journal != nil {
			journal = s.Journal.Ready()
		}
	}
	select {
	case <-ctx.Done():
	case <-pushed:
	case <-journal:
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
	s.tx++
	p.SentAt = time.Now().UnixNano()
	if s.fs() {
		out, err := s.sealFS(p)
		if err != nil {
			return err
		}
		return s.writeAll(out)
	}
	b, err := s.sealer.Seal(p)
	if err != nil {
		return err
	}
	addrs := s.Resolver.Addrs()
	if len(addrs) == 0 {
		s.Stats.SendErrors.Add(1)
		return errNoAddr
	}
	out := make([]datagram, len(addrs))
	for i, a := range addrs {
		out[i] = datagram{b, a}
	}
	return s.writeAll(out)
}

// writeAll sends each datagram to its server. It succeeds if at least one write worked.
func (s *Sender) writeAll(out []datagram) error {
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
	for _, d := range out {
		if _, err := s.conn.WriteTo(d.b, d.addr); err != nil {
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
