package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"lastgasp/internal/wire"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestParseKmsg(t *testing.T) {
	e, err := ParseKmsg([]byte("3,1234,5678901,-,caller=T1;EXT4-fs error: bad block\n SUBSYSTEM=block\n DEVICE=b8:0\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{Priority: 3, Seq: 1234, TsUsec: 5678901, Msg: "EXT4-fs error: bad block"}
	if e != want {
		t.Fatalf("got %+v, want %+v", e, want)
	}
	for _, bad := range []string{"", "no semicolon", "x,1,2,-;msg", "1,2;msg"} {
		if _, err := ParseKmsg([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// fakeSource replays canned read results.
type fakeSource struct {
	results []any // string or error
	closed  bool
}

func (f *fakeSource) Read(p []byte) (int, error) {
	if len(f.results) == 0 {
		return 0, io.EOF
	}
	r := f.results[0]
	f.results = f.results[1:]
	if err, ok := r.(error); ok {
		return 0, err
	}
	return copy(p, r.(string)), nil
}

func (f *fakeSource) Close() error { f.closed = true; return nil }

func TestKmsgReaderHandlesErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opens := 0
	var got []Entry
	stats := &Stats{}
	k := &KmsgReader{Stats: stats, Log: NewLogger(io.Discard, 10)}
	k.open = func(string) (recordSource, error) {
		opens++
		switch opens {
		case 1:
			return nil, syscall.ENOENT
		case 2:
			return &fakeSource{results: []any{"6,1,10,-;one", syscall.EPIPE, "garbage", "6,5,20,-;two", syscall.EIO}}, nil
		}
		cancel()
		return &fakeSource{}, nil
	}
	k.OnEntry = func(e Entry) { got = append(got, e) }
	k.Run(ctx)

	if len(got) != 2 || got[0].Msg != "one" || got[1].Msg != "two" {
		t.Fatalf("got %+v", got)
	}
	if stats.KmsgOverruns.Load() != 1 || stats.KmsgInvalid.Load() != 1 || stats.KmsgRead.Load() != 2 {
		t.Fatalf("stats overruns=%d invalid=%d read=%d", stats.KmsgOverruns.Load(), stats.KmsgInvalid.Load(), stats.KmsgRead.Load())
	}
	if opens < 3 {
		t.Fatalf("reader did not reopen after errors, opens=%d", opens)
	}
}

func TestParsePstore(t *testing.T) {
	data := []byte("Panic#1 Part1\n<6>[    0.000000] Linux version 6.9\n<0>[   12.5] Kernel panic - not syncing\r\n\nplain line\n")
	lines := ParsePstore(data)
	if len(lines) != 4 {
		t.Fatalf("got %d lines", len(lines))
	}
	if lines[0].Msg != "Panic#1 Part1" || lines[0].Priority != defaultPriority {
		t.Fatalf("header line: %+v", lines[0])
	}
	if lines[1].Msg != "Linux version 6.9" || lines[1].Priority != 6 || lines[1].TsUsec != 0 {
		t.Fatalf("line 1: %+v", lines[1])
	}
	if lines[2].Msg != "Kernel panic - not syncing" || lines[2].Priority != 0 || lines[2].TsUsec != 12_500_000 {
		t.Fatalf("line 2: %+v", lines[2])
	}
	if lines[3].Line != 4 {
		t.Fatalf("line numbers must follow the file, got %d", lines[3].Line)
	}
	if lines[0].FileID != FileID(data) || FileID(data) == FileID([]byte("other")) {
		t.Fatal("file id must depend only on content")
	}
}

func TestReadPstoreSkipsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "dmesg-ramoops-0"), []byte("<3>[1.000000] a\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "console-ramoops-0"), []byte("b\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ftrace-ramoops-0"), []byte("c\n"), 0o600)
	lines, err := ReadPstore(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0].Msg != "b" || lines[1].Msg != "a" {
		t.Fatalf("got %+v", lines)
	}
}

func TestQueueDropsOldest(t *testing.T) {
	q := NewQueue(2)
	q.Push(Item{Rec: wire.Record{Seq: 1}})
	q.Push(Item{Rec: wire.Record{Seq: 2}})
	if !q.Push(Item{Rec: wire.Record{Seq: 3}}) {
		t.Fatal("full queue did not report a drop")
	}
	it, _ := q.Peek()
	if it.Rec.Seq != 2 {
		t.Fatalf("oldest left should be 2, got %d", it.Rec.Seq)
	}
	// The peeked item gets dropped by a push; Done must not remove the wrong one.
	q.Push(Item{Rec: wire.Record{Seq: 4}})
	q.Done(it)
	if q.Len() != 2 {
		t.Fatalf("len %d, want 2", q.Len())
	}
	it, _ = q.Peek()
	q.Done(it)
	it, _ = q.Peek()
	q.Done(it)
	if _, ok := q.Peek(); ok || it.Rec.Seq != 4 {
		t.Fatal("queue should be empty after removing 3 and 4")
	}
}

func TestResolverKeepsLastGoodAddress(t *testing.T) {
	r, err := NewResolver([]string{"logs.example:5140", "10.0.0.9:5140"}, "")
	if err != nil {
		t.Fatal(err)
	}
	fail := false
	r.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if fail {
			return nil, errors.New("dns down")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	if len(r.Addrs()) != 1 {
		t.Fatal("literal ip should be known before any lookup")
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("expected lookup error")
	}
	addrs := r.Addrs()
	if len(addrs) != 2 || addrs[0].String() != "192.0.2.1:5140" {
		t.Fatalf("got %v", addrs)
	}
	if _, err := NewResolver([]string{"nope"}, ""); err == nil {
		t.Fatal("target without port accepted")
	}
}

type staticAddrs []*net.UDPAddr

func (s staticAddrs) Addrs() []*net.UDPAddr { return s }

// flakyConn fails the first n writes.
type flakyConn struct {
	mu    sync.Mutex
	fails int
	sent  [][]byte
}

func (f *flakyConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return 0, syscall.ENETUNREACH
	}
	f.sent = append(f.sent, append([]byte(nil), b...))
	return len(b), nil
}

func (f *flakyConn) Close() error { return nil }

func TestSenderRetriesWithoutSkippingSeq(t *testing.T) {
	conn := &flakyConn{fails: 3}
	q := NewQueue(10)
	for i := uint64(1); i <= 3; i++ {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Seq: i, Part: 1, Parts: 1, Msg: "m"}})
	}
	stats := &Stats{}
	s := &Sender{Host: "h", Key: testKey, Queue: q, Stats: stats, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}}
	s.newConn = func() (packetConn, error) { return conn, nil }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for q.Len() > 0 && ctx.Err() == nil {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	s.Run(ctx)

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.sent) != 3 {
		t.Fatalf("sent %d packets, want 3", len(conn.sent))
	}
	for i, b := range conn.sent {
		p, err := wire.Decode(b, func(string) []byte { return testKey })
		if err != nil {
			t.Fatal(err)
		}
		if p.Seq != uint64(i+1) || p.Record.Seq != uint64(i+1) {
			t.Fatalf("packet %d has seq %d record %d", i, p.Seq, p.Record.Seq)
		}
	}
	if stats.SendErrors.Load() != 3 {
		t.Fatalf("send errors %d, want 3", stats.SendErrors.Load())
	}
}

func TestSenderDropsUnsendableRecord(t *testing.T) {
	conn := &flakyConn{}
	q := NewQueue(10)
	q.Push(Item{Kind: wire.Kind(99)})
	q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: "ok"}})
	s := &Sender{Host: "h", Key: testKey, Queue: q, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}}
	s.newConn = func() (packetConn, error) { return conn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		for q.Len() > 0 && ctx.Err() == nil {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	s.Run(ctx)
	if len(conn.sent) != 1 {
		t.Fatalf("sent %d packets, want 1", len(conn.sent))
	}
}

func TestSenderHeartbeat(t *testing.T) {
	conn := &flakyConn{}
	s := &Sender{Host: "h", Key: testKey, Queue: NewQueue(1), Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}, Heartbeat: 20 * time.Millisecond}
	s.Stats.BufferDrops.Add(5)
	s.newConn = func() (packetConn, error) { return conn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	if len(conn.sent) < 3 {
		t.Fatalf("only %d heartbeats", len(conn.sent))
	}
	p, _ := wire.Decode(conn.sent[0], func(string) []byte { return testKey })
	if p.Kind != wire.KindHeartbeat || p.Stats.BufferDrops != 5 {
		t.Fatalf("bad heartbeat %+v", p)
	}
}

func TestSupervisorRestartsAfterPanic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runs := 0
	supervise(ctx, "test", NewLogger(io.Discard, 10), func(context.Context) {
		runs++
		if runs == 1 {
			panic("boom")
		}
		cancel()
	})
	if runs != 2 {
		t.Fatalf("runs %d, want 2", runs)
	}
}

func TestLoggerNeverBlocks(t *testing.T) {
	r, w := io.Pipe() // nobody reads, so writes block forever
	defer r.Close()
	l := NewLogger(w, 2)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			l.Printf("line %d", i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("logger blocked")
	}
	if l.Dropped.Load() == 0 {
		t.Fatal("expected dropped lines")
	}
}

func TestSenderSendsPstoreFirst(t *testing.T) {
	conn := &flakyConn{}
	q, ps := NewQueue(2), NewQueue(2)
	ps.Push(Item{Kind: wire.KindPstore, Rec: wire.Record{Msg: "panic"}})
	ps.Push(Item{Kind: wire.KindPstore, Rec: wire.Record{Msg: "trace"}})
	// A full kmsg queue drops its own oldest record, never a pstore line.
	for _, m := range []string{"k1", "k2", "k3"} {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}})
	}
	s := &Sender{Host: "h", Key: testKey, Queue: q, Pstore: ps, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}}
	s.newConn = func() (packetConn, error) { return conn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		for s.buffered() > 0 && ctx.Err() == nil {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	s.Run(ctx)
	var got []string
	for _, b := range conn.sent {
		p, err := wire.Decode(b, func(string) []byte { return testKey })
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p.Record.Msg)
	}
	if strings.Join(got, ",") != "panic,trace,k2,k3" {
		t.Fatalf("sent %v", got)
	}
}
