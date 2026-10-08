package agent

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"lastgasp/internal/wire"
)

// fsServer plays a version 5 server on the packets sent to a flakyConn.
type fsServer struct {
	t        *testing.T
	conn     *flakyConn
	seen     int
	inits    []fsInit
	sessions map[uint32]*wire.Session
	data     []fsData
	unknown  int // data packets of a session the server does not have
}

type fsInit struct {
	in *wire.Init
	to string
}

type fsData struct {
	p       *wire.Packet
	session uint32
	counter uint64
	to      string
}

func newFSServer(t *testing.T, conn *flakyConn) *fsServer {
	return &fsServer{t: t, conn: conn, sessions: map[uint32]*wire.Session{}}
}

// poll reads the packets sent since the last call.
func (f *fsServer) poll() {
	f.t.Helper()
	f.conn.mu.Lock()
	sent, to := f.conn.sent[f.seen:], f.conn.to[f.seen:]
	f.seen = len(f.conn.sent)
	f.conn.mu.Unlock()
	for i, b := range sent {
		h, err := wire.ParseHeader(b)
		if err != nil {
			f.t.Fatal(err)
		}
		switch h.Type {
		case wire.TypeInit:
			in, err := wire.ReadInit(b, func(string) []byte { return testKey })
			if err != nil {
				f.t.Fatal(err)
			}
			f.inits = append(f.inits, fsInit{in, to[i]})
		case wire.TypeData:
			s := f.sessions[h.Session]
			if s == nil {
				f.unknown++
				continue
			}
			p, err := s.Open(b)
			if err != nil {
				f.t.Fatal(err)
			}
			f.data = append(f.data, fsData{p, h.Session, h.Counter, to[i]})
		default:
			f.t.Fatalf("agent sent type %d", h.Type)
		}
	}
}

// waitFor polls until ok is true.
func (f *fsServer) waitFor(what string, ok func() bool) {
	f.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		f.poll()
		if ok() {
			return
		}
	}
	f.t.Fatalf("timeout waiting for %s", what)
}

// answer replies to init i and returns the session it starts.
func (f *fsServer) answer(i int) *wire.Session {
	f.t.Helper()
	s, reply, err := f.inits[i].in.Accept()
	if err != nil {
		f.t.Fatal(err)
	}
	f.sessions[s.ID] = s
	f.conn.acks <- reply
	return s
}

// record returns the data packet holding msg, or nil.
func (f *fsServer) record(msg string) *fsData {
	for i := range f.data {
		if f.data[i].p.Kind == wire.KindKmsg && f.data[i].p.Record.Msg == msg {
			return &f.data[i]
		}
	}
	return nil
}

func (f *fsServer) lastBeat() *fsData {
	for i := len(f.data) - 1; i >= 0; i-- {
		if f.data[i].p.Kind == wire.KindHeartbeat {
			return &f.data[i]
		}
	}
	return nil
}

func fsSender(conn *flakyConn, q *Queue, hb time.Duration, addrs ...*net.UDPAddr) *Sender {
	if len(addrs) == 0 {
		addrs = []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
	}
	s := &Sender{Host: "h", Instance: 7, Key: testKey, Queue: q, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs(addrs), Heartbeat: hb, WaitAck: true, ForwardSecrecy: true}
	s.newConn = func() (packetConn, error) { return conn, nil }
	return s
}

func TestSenderFSHoldsRecordsUntilHandshake(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 16)}
	f := newFSServer(t, conn)
	q := NewQueue(10)
	for _, m := range []string{"a", "b"} {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}})
	}
	s := fsSender(conn, q, 200*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)

	f.waitFor("an init", func() bool { return len(f.inits) > 0 })
	time.Sleep(50 * time.Millisecond)
	f.poll()
	if len(f.data) != 0 || q.Len() != 2 {
		t.Fatalf("sent %d data packets before the handshake", len(f.data))
	}
	// Junk and a reply to a handshake the agent never started change nothing.
	conn.acks <- []byte("junk")
	in, _ := wire.ReadInit(mustInit(t, 7), func(string) []byte { return testKey })
	_, stray, _ := in.Accept()
	conn.acks <- stray
	time.Sleep(50 * time.Millisecond)
	f.poll()
	if len(f.data) != 0 {
		t.Fatal("records sent after a stray reply")
	}

	sess := f.answer(len(f.inits) - 1)
	// The ack must answer a heartbeat sent after the records to confirm them.
	f.waitFor("records and a heartbeat after them", func() bool {
		b := f.record("b")
		return f.record("a") != nil && b != nil && f.lastBeat() != nil && f.lastBeat().p.Seq > b.p.Seq
	})
	if f.data[0].p.Seq != 1 {
		t.Fatalf("first seq %d", f.data[0].p.Seq)
	}
	if q.Len() != 2 {
		t.Fatal("records left the queue before an ack")
	}
	beat := f.lastBeat()
	ack, _ := sess.SealAck(beat.p, beat.p.Seq, nil)
	conn.acks <- ack
	f.waitFor("records confirmed", func() bool { return q.Len() == 0 })
}

// mustInit makes a handshake init of another session of agent run inst.
func mustInit(t *testing.T, inst uint64) []byte {
	t.Helper()
	_, b, err := wire.StartHandshake(testKey, "h", [16]byte{}, inst, 1)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSenderFSHandshakesAgainWhenAcksStop(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 16)}
	f := newFSServer(t, conn)
	q := NewQueue(10)
	s := fsSender(conn, q, 30*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)

	f.waitFor("an init", func() bool { return len(f.inits) == 1 })
	f.answer(0)
	f.waitFor("a heartbeat", func() bool { return f.lastBeat() != nil })
	// Heartbeats get no ack, as after a server restart: after three of them the agent starts over.
	f.waitFor("a second init", func() bool { return len(f.inits) == 2 })
	if f.inits[1].in.Number <= f.inits[0].in.Number {
		t.Fatalf("handshake numbers %d then %d", f.inits[0].in.Number, f.inits[1].in.Number)
	}
	if s.ready() {
		t.Fatal("agent still sending without acks")
	}
}

func TestSenderFSRekeys(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 16)}
	f := newFSServer(t, conn)
	q := NewQueue(10)
	s := fsSender(conn, q, time.Hour)
	var off atomic.Int64
	base := time.Now()
	s.clock = func() time.Time { return base.Add(time.Duration(off.Load())) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)
	push := func(m string) { q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}}) }

	f.waitFor("an init", func() bool { return len(f.inits) == 1 })
	a := f.answer(0)
	push("a")
	f.waitFor("a", func() bool { return f.record("a") != nil })

	// After two minutes a new handshake starts, and records still go with the old session meanwhile.
	off.Store(int64(wire.RekeyAfter + time.Second))
	push("b")
	f.waitFor("a rekey init and b", func() bool { return len(f.inits) == 2 && f.record("b") != nil })
	if f.record("b").session != a.ID {
		t.Fatal("b not sent with the old session")
	}
	b := f.answer(1)
	time.Sleep(20 * time.Millisecond)
	push("c")
	f.waitFor("c", func() bool { return f.record("c") != nil })
	if f.record("c").session != b.ID {
		t.Fatal("c not sent with the new session")
	}

	// A session too old is dropped: records wait for a new handshake.
	off.Store(int64(wire.RekeyAfter + time.Second + wire.RejectAfter))
	push("d")
	f.waitFor("a third init", func() bool { return len(f.inits) == 3 })
	time.Sleep(20 * time.Millisecond)
	f.poll()
	if f.record("d") != nil {
		t.Fatal("d sent with an expired session")
	}
}

func TestSenderFSOneSessionPerServer(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 16)}
	f := newFSServer(t, conn)
	q := NewQueue(10)
	one, two := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
	s := fsSender(conn, q, time.Hour, one, two)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)
	push := func(m string) { q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}}) }
	initTo := func(addr string) int {
		for i := len(f.inits) - 1; i >= 0; i-- {
			if f.inits[i].to == addr {
				return i
			}
		}
		return -1
	}

	f.waitFor("inits to both", func() bool { return initTo(one.String()) >= 0 && initTo(two.String()) >= 0 })
	f.answer(initTo(one.String()))
	push("a")
	f.waitFor("a", func() bool { return f.record("a") != nil })
	time.Sleep(20 * time.Millisecond)
	f.poll()
	for _, d := range f.data {
		if d.to != one.String() {
			t.Fatalf("data sent to %s, which has no session", d.to)
		}
	}

	f.answer(initTo(two.String()))
	time.Sleep(20 * time.Millisecond)
	push("b")
	f.waitFor("b to both", func() bool {
		n := 0
		for _, d := range f.data {
			if d.p.Record.Msg == "b" {
				n++
			}
		}
		return n == 2
	})
	if f.unknown != 0 {
		t.Fatalf("%d packets with a session of the other server", f.unknown)
	}
}

func TestSenderFSRestartKeepsSession(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 16)}
	f := newFSServer(t, conn)
	q := NewQueue(10)
	s := fsSender(conn, q, time.Hour)
	push := func(m string) { q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}}) }

	// Run twice, as the supervisor does after a panic.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	f.waitFor("an init", func() bool { return len(f.inits) == 1 })
	f.answer(0)
	push("a")
	f.waitFor("a", func() bool { return f.record("a") != nil })
	cancel()
	<-done

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)
	push("b")
	f.waitFor("b", func() bool { return f.record("b") != nil })
	if len(f.inits) != 1 {
		t.Fatalf("%d handshakes, the session should survive the restart", len(f.inits))
	}
	seen := map[uint64]bool{}
	for _, d := range f.data {
		if seen[d.counter] {
			t.Fatalf("counter %d used twice", d.counter)
		}
		seen[d.counter] = true
	}
}
