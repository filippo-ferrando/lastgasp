package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"lastgasp/internal/agent"
	"lastgasp/internal/incident"
	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

// handshake runs a version 5 handshake against the ingestor and returns the agent session.
func handshake(t *testing.T, in *Ingestor, inst, number uint64) *wire.Session {
	t.Helper()
	hs, init, err := wire.StartHandshake(testKey, "node-1", [16]byte{1}, inst, number)
	if err != nil {
		t.Fatal(err)
	}
	reply := in.Handle(init, nil)
	if reply == nil {
		t.Fatal("no handshake reply")
	}
	s, err := hs.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sealed(t *testing.T, s *wire.Session, p *wire.Packet) []byte {
	t.Helper()
	b, err := s.Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestForwardSecrecyIngest(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	r := &replies{}
	e.in.SetReply(r.add)
	s := handshake(t, e.in, 1, 1)
	for i, msg := range []string{"a", "b"} {
		e.in.Handle(sealed(t, s, kmsgPkt(1, 1, uint64(i+1), uint64(i), 1, msg)), nil)
	}
	e.waitRecords(t, 2)
	beat := pkt("node-1", 1, 1, 3)
	beat.SentAt = 99
	e.in.Handle(sealed(t, s, beat), nil)
	var ack wire.Ack
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		r.mu.Lock()
		n := len(r.acks)
		r.mu.Unlock()
		if n > 0 {
			var err error
			if ack, err = s.OpenAck(r.acks[0]); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if ack.SentAt != 99 || ack.Upto != 3 || len(ack.Missing) != 0 {
		t.Fatalf("ack %+v", ack)
	}

	m := e.get(t, "/metrics")
	if !strings.Contains(m, "lastgasp_handshakes_total 1") {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestForwardSecrecyRefusesReplays(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	hs, init, _ := wire.StartHandshake(testKey, "node-1", [16]byte{1}, 1, 5)
	reply := e.in.Handle(init, nil)
	s, err := hs.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(ackEvery)
	// The same init, or one with a lower number, gets no answer.
	if e.in.Handle(init, nil) != nil {
		t.Fatal("replayed init answered")
	}
	_, old, _ := wire.StartHandshake(testKey, "node-1", [16]byte{1}, 1, 4)
	if e.in.Handle(old, nil) != nil {
		t.Fatal("init with an old number answered")
	}
	b := sealed(t, s, kmsgPkt(1, 1, 1, 0, 1, "once"))
	e.in.Handle(b, nil)
	e.in.Handle(b, nil)
	e.waitRecords(t, 1)
	// A session moved to another agent run is unknown there, a changed packet fails.
	other := handshake(t, e.in, 2, 1)
	b = sealed(t, other, kmsgPkt(1, 2, 1, 1, 1, "x"))
	b[6+len("node-1")+16+7] = 1
	e.in.Handle(b, nil)
	b = sealed(t, other, kmsgPkt(1, 2, 1, 1, 1, "x"))
	b[len(b)-1] ^= 1
	e.in.Handle(b, nil)

	m := e.get(t, "/metrics")
	for _, want := range []string{`reason="replay"} 3`, `reason="unknown_session"} 1`, `reason="auth_failed"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s:\n%s", want, m)
		}
	}
}

func TestSessionsKeepWorkingOnesAndExpire(t *testing.T) {
	ss := NewSessions()
	k := ackKey{"node-1", [16]byte{1}, 1}
	now := time.Now()
	mk := func(id uint32) *wire.Session { return &wire.Session{ID: id} }
	a, b := mk(1), mk(2)
	ss.Add(k, 1, a, now)
	ss.Confirm(k, a)
	if ss.Lookup(k, 1, now) != a {
		t.Fatal("current session not found")
	}
	// Replayed or stray handshakes fill the pending slots but never push out the current session.
	for i := uint32(10); i < 20; i++ {
		ss.Add(k, uint64(i), mk(i), now)
	}
	if ss.Lookup(k, 1, now) != a || ss.Lookup(k, 10, now) != nil || ss.Lookup(k, 19, now) == nil {
		t.Fatal("pending sessions not bounded, or current session lost")
	}
	if ss.Fresh(k, 19) || !ss.Fresh(k, 20) {
		t.Fatal("handshake numbers not checked")
	}
	// The newest session takes over with its first data, the old one stays as previous.
	ss.Add(k, 20, b, now)
	ss.Confirm(k, b)
	if ss.Lookup(k, 1, now) != a || ss.Lookup(k, 2, now) != b || ss.Lookup(k, 19, now) != nil {
		t.Fatal("previous session lost, or older pending ones kept")
	}
	later := now.Add(wire.RejectAfter)
	if ss.Lookup(k, 2, later) != nil {
		t.Fatal("expired session still accepted")
	}
	ss.Sweep(later)
	if ss.Len() != 0 {
		t.Fatal("expired sessions not swept")
	}
}

func TestForwardSecrecyKeyRemovedAndRequired(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	s := handshake(t, e.in, 1, 1)
	keys := e.in.Keys
	e.in.Keys = noKeys{}
	e.in.Handle(sealed(t, s, kmsgPkt(1, 1, 1, 0, 1, "gone")), nil)
	e.in.Keys = keys
	e.in.RequireFS = true
	b, _ := wire.Encode(kmsgPkt(1, 1, 2, 1, 1, "old"), testKey)
	e.in.Handle(b, nil)
	e.in.Handle(sealed(t, s, kmsgPkt(1, 1, 3, 2, 1, "new")), nil)
	recs := e.waitRecords(t, 1)
	if recs[0].Message != "new" {
		t.Fatalf("records %+v", recs)
	}
	m := e.get(t, "/metrics")
	for _, want := range []string{`reason="unknown_host"} 1`, `reason="version"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

type noKeys struct{}

func (noKeys) Lookup(string) []byte { return nil }

// switchProxy forwards UDP between one agent and the server in target, which can change.
func switchProxy(t *testing.T, target *atomic.Pointer[string]) net.Addr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65536)
		var agentAddr net.Addr
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			to, _ := net.ResolveUDPAddr("udp", *target.Load())
			if from.String() == to.String() {
				if agentAddr != nil {
					conn.WriteTo(buf[:n], agentAddr)
				}
				continue
			}
			agentAddr = from
			conn.WriteTo(buf[:n], to)
		}
	}()
	return conn.LocalAddr()
}

func listen(t *testing.T, e *env) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.in.Listen(conn)
	return conn
}

// TestForwardSecrecyEndToEnd runs agent and server over UDP, with a server restart that loses the sessions.
func TestForwardSecrecyEndToEnd(t *testing.T) {
	db := filepath.Join(t.TempDir(), "db")
	e := newEnv(t, db)
	conn := listen(t, e)
	var target atomic.Pointer[string]
	addr := conn.LocalAddr().String()
	target.Store(&addr)
	proxy := switchProxy(t, &target)

	res, err := agent.NewResolver([]string{proxy.String()}, "")
	if err != nil {
		t.Fatal(err)
	}
	q := agent.NewQueue(100)
	push := func(i int, msg string) {
		q.Push(agent.Item{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 4, Seq: uint64(i), Part: 1, Parts: 1, Msg: msg}})
	}
	push(0, "before restart")
	s := &agent.Sender{Host: "node-1", Instance: 1, Key: testKey, Queue: q, Resolver: res, Stats: &agent.Stats{},
		Log: agent.NewLogger(io.Discard, 10), Heartbeat: 100 * time.Millisecond, WaitAck: true, ForwardSecrecy: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	e.waitRecords(t, 1)
	for deadline := time.Now().Add(5 * time.Second); q.Len() > 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if q.Len() != 0 {
		t.Fatal("record not confirmed")
	}

	// The server restarts on another port and forgets every session.
	conn.Close()
	e.stop()
	e2 := newEnv(t, db)
	conn2 := listen(t, e2)
	defer conn2.Close()
	addr2 := conn2.LocalAddr().String()
	target.Store(&addr2)
	push(1, "after restart")

	recs := e2.waitRecords(t, 2)
	if recs[1].Message != "after restart" {
		t.Fatalf("records %+v", recs)
	}
	for deadline := time.Now().Add(5 * time.Second); q.Len() > 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if q.Len() != 0 {
		t.Fatal("record not confirmed by the new server")
	}
	// One handshake, or more when an ack was slower than three heartbeats.
	if m := e2.get(t, "/metrics"); strings.Contains(m, "lastgasp_handshakes_total 0\n") {
		t.Fatalf("the agent did not make a new handshake with the restarted server:\n%s", grepLines(m, "handshakes|invalid"))
	}
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		for _, w := range strings.Split(sub, "|") {
			if strings.Contains(l, w) && !strings.HasPrefix(l, "#") {
				out = append(out, l)
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

func TestWireVersionAndSessionsShown(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	s := handshake(t, e.in, 1, 1)
	e.in.Handle(sealed(t, s, kmsgPkt(1, 1, 1, 0, 1, "new")), nil)
	old := kmsgPkt(1, 1, 1, 0, 1, "old")
	old.Host = "node-2"
	e.send(t, old)
	e.waitRecords(t, 2)

	var hosts []HostSummary
	if err := json.Unmarshal([]byte(e.get(t, "/api/hosts")), &hosts); err != nil {
		t.Fatal(err)
	}
	versions := map[string]uint8{}
	for _, h := range hosts {
		versions[h.Host] = h.Wire
	}
	if versions["node-1"] != 5 || versions["node-2"] != 4 {
		t.Fatalf("wire versions %v", versions)
	}
	m := e.get(t, "/metrics")
	for _, want := range []string{`lastgasp_agent_wire_version{host="node-1"} 5`, `lastgasp_agent_wire_version{host="node-2"} 4`,
		"lastgasp_sessions 1"} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	if page := e.get(t, "/"); !strings.Contains(page, "h.wire_version") {
		t.Error("hosts table has no wire version column")
	}
}

func TestSelfCheckReplays(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	sc := &SelfCheck{Detector: e.det, Checks: ServerChecks(e.metrics, incident.NewMetrics(prometheus.NewRegistry()))}
	ctx := context.Background()
	sc.RunOnce(ctx, time.Now())
	s := handshake(t, e.in, 1, 1)
	b := sealed(t, s, kmsgPkt(1, 1, 1, 0, 1, "x"))
	replay := func(n int) {
		for range n {
			e.in.Handle(b, nil)
		}
	}
	// The first copy is stored, the rest are replays. A few of them are network noise.
	replay(replayMin)
	sc.RunOnce(ctx, time.Now())
	e.det.Flush(ctx)
	if l, _ := e.st.Incidents(ctx, store.IncidentFilter{Kind: incident.KindServer}); len(l) != 0 {
		t.Fatalf("incident for %d replays: %+v", replayMin-1, l)
	}
	replay(replayMin)
	sc.RunOnce(ctx, time.Now())
	e.det.Flush(ctx)
	l, err := e.st.Incidents(ctx, store.IncidentFilter{Kind: incident.KindServer})
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].Rule != "replay" || l[0].Count != replayMin {
		t.Fatalf("incidents %+v", l)
	}
}

func TestSessionsFullTableKeepsWorkingOnes(t *testing.T) {
	ss := NewSessions()
	now := time.Now()
	run := func(host string, i int) ackKey { return ackKey{host, [16]byte{1}, uint64(i)} }
	live := run("node-1", 0)
	ss.Add(live, 1, &wire.Session{ID: 1}, now)
	ss.Confirm(live, ss.Lookup(live, 1, now))
	// One host with many runs keeps its working one and at most maxRunsPerHost.
	for i := 1; i < 100; i++ {
		ss.Add(run("node-1", i), 1, &wire.Session{ID: 2}, now)
	}
	if ss.Len() != maxRunsPerHost || ss.Lookup(live, 1, now) == nil {
		t.Fatalf("%d runs, working session lost: %v", ss.Len(), ss.Lookup(live, 1, now) == nil)
	}
	// Handshakes with made up runs fill the table: the working session stays.
	for i := 0; ss.Len() < cacheLimit; i++ {
		ss.Add(run(strconv.Itoa(i/maxRunsPerHost), i), 1, &wire.Session{ID: 2}, now)
	}
	ss.Add(run("new", 0), 1, &wire.Session{ID: 3}, now)
	if ss.Lookup(live, 1, now) == nil || ss.Lookup(run("new", 0), 3, now) == nil || ss.Len() >= cacheLimit {
		t.Fatalf("full table: %d runs", ss.Len())
	}
}
