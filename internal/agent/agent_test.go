package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
		case 3:
			// A reopened device starts again at the oldest record, those already read are skipped.
			return &fakeSource{results: []any{"6,1,10,-;one", "6,5,20,-;two", "6,6,30,-;three", syscall.EIO}}, nil
		}
		cancel()
		return &fakeSource{}, nil
	}
	k.OnEntry = func(e Entry) { got = append(got, e) }
	k.Run(ctx)

	if len(got) != 3 || got[0].Msg != "one" || got[1].Msg != "two" || got[2].Msg != "three" {
		t.Fatalf("got %+v", got)
	}
	if stats.KmsgOverruns.Load() != 1 || stats.KmsgInvalid.Load() != 1 || stats.KmsgRead.Load() != 3 {
		t.Fatalf("stats overruns=%d invalid=%d read=%d", stats.KmsgOverruns.Load(), stats.KmsgInvalid.Load(), stats.KmsgRead.Load())
	}
	if opens < 4 {
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

func TestParsePstoreJoinsMultiLineRecords(t *testing.T) {
	// One record printed with two lines, then one with a tab, a backslash and UTF-8, as /dev/kmsg escapes them.
	data := []byte("<4>[    2.000000] first line\n<4>[    2.000000] second\n" +
		"<4>[    2.000001] tab\there \\ caf\u00e9\n" +
		"<4>[    2.000002] before an empty line\n\n<4>[    2.000002] not joined\n" +
		"plain\nplain again\n")
	lines := ParsePstore(data)
	var got []string
	for _, l := range lines {
		got = append(got, fmt.Sprint(l.Line, ":", l.Msg))
	}
	want := []string{`0:first line\x0asecond`, `2:tab\x09here \x5c caf\xc3\xa9`, "3:before an empty line", "5:not joined",
		"6:plain", "7:plain again"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	// The joined record reads like its /dev/kmsg copy.
	k, err := ParseKmsg([]byte("4,9,2000000,-;first line\\x0asecond\n"))
	if err != nil || k.Msg != lines[0].Msg || k.TsUsec != lines[0].TsUsec || k.Priority != lines[0].Priority {
		t.Fatalf("kmsg %+v, pstore %+v", k, lines[0])
	}
}

func TestReadPstoreSkipsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "dmesg-ramoops-0"), []byte("<3>[1.000000] a\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "console-ramoops-0"), []byte("b\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ftrace-ramoops-0"), []byte("c\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "dmesg-efi-171234-1.enc.z"), []byte("\x78\x9c binary\n"), 0o600)
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
	it, _ := q.Next()
	if it.Rec.Seq != 2 {
		t.Fatalf("oldest left should be 2, got %d", it.Rec.Seq)
	}
	// The item from Next gets dropped by a push; Sent must not mark the wrong one.
	q.Push(Item{Rec: wire.Record{Seq: 4}})
	q.Sent(it, 1, 1, false)
	if q.Len() != 2 {
		t.Fatalf("len %d, want 2", q.Len())
	}
	for seq := uint64(2); seq <= 3; seq++ {
		it, _ = q.Next()
		q.Sent(it, seq, seq, false)
	}
	if _, ok := q.Next(); ok || it.Rec.Seq != 4 || q.Len() != 0 {
		t.Fatal("queue should be empty after sending 3 and 4")
	}
}

// sendAll sends every item of q as packets with seq first, first+1, ..., one transmission each.
func sendAll(q *Queue, first uint64) {
	for seq := first; ; seq++ {
		it, ok := q.Next()
		if !ok {
			return
		}
		q.Sent(it, seq, seq, true)
	}
}

func TestQueueKeepsSentItemsUntilAck(t *testing.T) {
	q := NewQueue(10)
	for i := 1; i <= 5; i++ {
		q.Push(Item{Rec: wire.Record{Seq: uint64(i)}})
	}
	sendAll(q, 1)
	if q.Len() != 5 || q.Unconfirmed() != 5 || q.Oldest() != 1 {
		t.Fatalf("len %d unconfirmed %d oldest %d", q.Len(), q.Unconfirmed(), q.Oldest())
	}
	// The server got 1 to 4 except 2. 5 may still be on its way.
	q.Ack(4, []wire.Range{{From: 2, To: 2}}, 6)
	if q.Len() != 2 || q.Oldest() != 2 {
		t.Fatalf("len %d oldest %d", q.Len(), q.Oldest())
	}
	it, ok := q.Next()
	if !ok || it.seq != 2 {
		t.Fatalf("next %+v, want a resend of seq 2", it)
	}
	q.Sent(it, 0, 7, true)
	if _, ok := q.Next(); ok {
		t.Fatal("seq 2 sent again twice")
	}
	// An ack for a heartbeat older than the resend does not trigger another one.
	q.Ack(4, []wire.Range{{From: 2, To: 2}}, 6)
	if _, ok := q.Next(); ok {
		t.Fatal("resent for an old ack")
	}
	q.Ack(5, nil, 8)
	if q.Len() != 0 || q.Oldest() != 0 {
		t.Fatalf("len %d oldest %d after the full ack", q.Len(), q.Oldest())
	}
}

func TestQueueDropsSentItemsFirstWhenFull(t *testing.T) {
	q := NewQueue(3)
	for i := 1; i <= 3; i++ {
		q.Push(Item{Rec: wire.Record{Seq: uint64(i)}})
	}
	sendAll(q, 10)
	// A sent item most likely arrived, so dropping it is not counted.
	if q.Push(Item{Rec: wire.Record{Seq: 4}}) {
		t.Fatal("sent item counted as dropped")
	}
	if q.Oldest() != 11 || q.Len() != 3 {
		t.Fatalf("oldest %d len %d", q.Oldest(), q.Len())
	}
	// A seq listed as missing after its item was dropped is skipped.
	q.Ack(12, []wire.Range{{From: 10, To: 10}}, 100)
	if it, ok := q.Next(); !ok || it.seq != 0 || it.Rec.Seq != 4 {
		t.Fatalf("next %+v", it)
	}
	if q.Len() != 1 {
		t.Fatalf("len %d", q.Len())
	}
}

func TestQueueDrop(t *testing.T) {
	q := NewQueue(4)
	for i := 1; i <= 3; i++ {
		q.Push(Item{Rec: wire.Record{Seq: uint64(i)}})
	}
	it, _ := q.Next()
	q.Sent(it, 5, 1, true)
	it, _ = q.Next()
	q.Drop(it)
	it, _ = q.Next()
	q.Sent(it, 6, 2, true)
	// Seq order holds after a drop, so an ack still finds every item.
	q.Ack(6, []wire.Range{{From: 6, To: 6}}, 3)
	if it, ok := q.Next(); !ok || it.seq != 6 || q.Len() != 1 {
		t.Fatalf("next %+v len %d", it, q.Len())
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

// flakyConn fails the first n writes. Reads return what is put in acks, and block while it is nil.
type flakyConn struct {
	mu    sync.Mutex
	fails int
	sent  [][]byte
	to    []string // address of each sent packet
	acks  chan []byte
}

func (f *flakyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	ack, ok := <-f.acks
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(b, ack), nil, nil
}

func (f *flakyConn) packets(t *testing.T) []*wire.Packet {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*wire.Packet
	for _, b := range f.sent {
		p, err := wire.Decode(b, func(string) []byte { return testKey })
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func (f *flakyConn) WriteTo(b []byte, a net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return 0, syscall.ENETUNREACH
	}
	f.sent = append(f.sent, append([]byte(nil), b...))
	f.to = append(f.to, a.String())
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
	s := &Sender{Host: "h", Key: testKey, Queue: q, First: ps, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
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

func TestSenderHoldsRecordsUntilAck(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 1)}
	q := NewQueue(10)
	for _, m := range []string{"a", "b"} {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}})
	}
	s := &Sender{Host: "h", Instance: 7, Key: testKey, Queue: q, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}, Heartbeat: 20 * time.Millisecond, WaitAck: true}
	s.newConn = func() (packetConn, error) { return conn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go s.Run(ctx)

	time.Sleep(80 * time.Millisecond)
	for _, p := range conn.packets(t) {
		if p.Kind != wire.KindHeartbeat || p.Seq != 0 {
			t.Fatalf("sent %v seq %d before any ack", p.Kind, p.Seq)
		}
	}
	if q.Len() != 2 {
		t.Fatalf("queue has %d records, want 2", q.Len())
	}

	probes := conn.packets(t)
	probe := probes[len(probes)-1]
	// Acks for another agent run, or for a heartbeat that is not recent, are ignored.
	other := *probe
	other.Instance = 8
	old := *probe
	old.SentAt = 12345
	for _, p := range []*wire.Packet{&other, &old} {
		bad, _ := wire.EncodeAck(p, 0, nil, testKey)
		conn.acks <- bad
	}
	time.Sleep(50 * time.Millisecond)
	if q.Len() != 2 {
		t.Fatal("records sent after a bad ack")
	}

	ack, _ := wire.EncodeAck(probe, 0, nil, testKey)
	conn.acks <- ack
	var msgs []string
	var seqs []uint64
	var beat *wire.Packet
	for ctx.Err() == nil && (len(msgs) < 2 || beat == nil) {
		time.Sleep(5 * time.Millisecond)
		msgs, seqs, beat = nil, nil, nil
		for _, p := range conn.packets(t) {
			if p.Seq == 0 {
				continue
			}
			seqs = append(seqs, p.Seq)
			if p.Kind == wire.KindKmsg {
				msgs = append(msgs, p.Record.Msg)
			} else if len(msgs) == 2 {
				beat = p
			}
		}
	}
	if strings.Join(msgs, ",") != "a,b" || seqs[0] != 1 {
		t.Fatalf("sent %v with seqs %v", msgs, seqs)
	}
	// Sent records stay until a server confirms them.
	if q.Len() != 2 || beat.Oldest != 1 {
		t.Fatalf("queue has %d records, heartbeat oldest %d", q.Len(), beat.Oldest)
	}
	ack, _ = wire.EncodeAck(beat, beat.Seq, nil, testKey)
	conn.acks <- ack
	for q.Len() > 0 && ctx.Err() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	if q.Len() != 0 {
		t.Fatal("records not released by the ack")
	}
}

func TestSenderResendsMissingRecords(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 1)}
	q := NewQueue(10)
	for _, m := range []string{"a", "b", "c"} {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}})
	}
	s := &Sender{Host: "h", Instance: 7, Key: testKey, Queue: q, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}, Heartbeat: 30 * time.Millisecond, WaitAck: true}
	s.newConn = func() (packetConn, error) { return conn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go s.Run(ctx)

	// waitFor returns the first packet after skip packets that matches ok.
	waitFor := func(skip int, ok func(*wire.Packet) bool) (*wire.Packet, int) {
		for ctx.Err() == nil {
			ps := conn.packets(t)
			for i := skip; i < len(ps); i++ {
				if ok(ps[i]) {
					return ps[i], i + 1
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("timeout")
		return nil, 0
	}
	probe, _ := waitFor(0, func(p *wire.Packet) bool { return p.Kind == wire.KindHeartbeat })
	ack, _ := wire.EncodeAck(probe, 0, nil, testKey)
	conn.acks <- ack
	_, n := waitFor(0, func(p *wire.Packet) bool { return p.Record.Msg == "c" })
	beat, n := waitFor(n, func(p *wire.Packet) bool { return p.Kind == wire.KindHeartbeat && p.Seq != 0 })

	// The server lost the packet of "b" and tells so.
	var bSeq uint64
	for _, p := range conn.packets(t) {
		if p.Record.Msg == "b" {
			bSeq = p.Seq
		}
	}
	ack, _ = wire.EncodeAck(beat, beat.Seq, []wire.Range{{From: bSeq, To: bSeq}}, testKey)
	conn.acks <- ack
	again, _ := waitFor(n, func(p *wire.Packet) bool { return p.Kind == wire.KindKmsg })
	if again.Record.Msg != "b" || again.Seq != bSeq {
		t.Fatalf("sent again %q with seq %d, want b with seq %d", again.Record.Msg, again.Seq, bSeq)
	}
	for q.Len() != 1 && ctx.Err() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	// Until "b" is confirmed the next heartbeat says it can still come.
	beat, _ = waitFor(n, func(p *wire.Packet) bool { return p.Kind == wire.KindHeartbeat && p.Seq > beat.Seq })
	if beat.Oldest != bSeq {
		t.Fatalf("heartbeat oldest %d, want %d", beat.Oldest, bSeq)
	}
}

func TestSenderSendsEarlyHeartbeatWhenBufferWaits(t *testing.T) {
	conn := &flakyConn{acks: make(chan []byte, 1)}
	q := NewQueue(4)
	for _, m := range []string{"a", "b"} {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}})
	}
	s := &Sender{Host: "h", Key: testKey, Queue: q, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}, Heartbeat: time.Hour, WaitAck: true}
	s.newConn = func() (packetConn, error) { return conn, nil }
	// Pretend a server answered a moment ago.
	s.init()
	s.lastAck.Store(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go s.Run(ctx)
	for ctx.Err() == nil {
		beats := 0
		for _, p := range conn.packets(t) {
			if p.Kind == wire.KindHeartbeat {
				beats++
			}
		}
		// One at start, one more because half the buffer waits for a server.
		if beats >= 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no early heartbeat")
}

// nonceCounter reads the clear nonce counter of a sealed packet.
func nonceCounter(b []byte) uint64 {
	off := 6 + int(b[5]) + 16 + 8
	return binary.BigEndian.Uint64(b[off : off+8])
}

func TestSenderRestartKeepsNoncesUnique(t *testing.T) {
	conn := &flakyConn{}
	q := NewQueue(10)
	s := &Sender{Host: "h", Key: testKey, Queue: q, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}}
	s.newConn = func() (packetConn, error) { return conn, nil }
	// Run twice, as the supervisor does after a panic.
	for _, m := range []string{"a", "b"} {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: m}})
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for q.Len() > 0 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}()
		s.Run(ctx)
	}
	seen := map[uint64]bool{}
	for _, b := range conn.sent {
		c := nonceCounter(b)
		if seen[c] {
			t.Fatalf("nonce counter %d used twice", c)
		}
		seen[c] = true
	}
	if len(seen) != 2 {
		t.Fatalf("sent %d packets", len(seen))
	}
}

func TestSenderDrainsOnShutdown(t *testing.T) {
	conn := &flakyConn{}
	q := NewQueue(100)
	s := &Sender{Host: "h", Key: testKey, Queue: q, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}, Rate: 1}
	s.newConn = func() (packetConn, error) { return conn, nil }
	for i := 0; i < 50; i++ {
		q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Msg: "m"}})
	}
	// At one packet per second almost nothing goes out before the stop, the drain sends the rest unpaced.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	if q.Len() != 0 {
		t.Fatalf("%d records left after shutdown", q.Len())
	}
}

func TestConfigValidate(t *testing.T) {
	good := func() Config {
		return Config{Servers: []string{"logs:5140"}, Host: "h", Key: testKey, BufferSize: 10, Rate: 100,
			Heartbeat: 5 * time.Second, ResolveEvery: time.Minute, WaitAck: true}
	}
	if c := good(); c.Validate() != nil {
		t.Fatal(c.Validate())
	}
	for name, change := range map[string]func(*Config){
		"no server":         func(c *Config) { c.Servers = nil },
		"server port":       func(c *Config) { c.Servers = []string{"logs"} },
		"bad host":          func(c *Config) { c.Host = "a b" },
		"short key":         func(c *Config) { c.Key = []byte("x") },
		"buffer 0":          func(c *Config) { c.BufferSize = 0 },
		"buffer too big":    func(c *Config) { c.BufferSize = MaxBuffer + 1 },
		"negative rate":     func(c *Config) { c.Rate = -1 },
		"tiny heartbeat":    func(c *Config) { c.Heartbeat = time.Millisecond },
		"wait-ack no beats": func(c *Config) { c.Heartbeat = 0 },
		"resolve loop":      func(c *Config) { c.ResolveEvery = 0 },
		"dns without port":  func(c *Config) { c.DNSServer = "10.0.0.53" },
	} {
		c := good()
		change(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePstoreDropsCallerID(t *testing.T) {
	lines := ParsePstore([]byte("<4>[    5.100000] [ T2048] marker\n<6>[    5.200000] [    C1] cpu line\n[    5.300000] [T7] console line\n"))
	if len(lines) != 3 || lines[0].Msg != "marker" || lines[1].Msg != "cpu line" || lines[2].Msg != "console line" {
		t.Fatalf("lines %+v", lines)
	}
}

func TestReadPstoreArchive(t *testing.T) {
	dir := t.TempDir()
	boot := time.Now().Add(-time.Hour)
	write := func(name, content string, mtime time.Time) {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(content), 0o600)
		os.Chtimes(p, mtime, mtime)
	}
	write("pmsg-ramoops-0", "moved this boot\n", time.Now())
	write("console-ramoops-0", "moved in an older boot\n", boot.Add(-time.Hour))
	write("171234/dmesg.txt", "<0>[    5.000000] Kernel panic - not syncing: x\n", time.Now())
	write("171234/deeper/dmesg-ramoops-0", "too deep\n", time.Now())
	write("notes.txt", "not a pstore file\n", time.Now())
	lines, err := ReadPstoreArchive(dir, boot, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range lines {
		got = append(got, l.Msg)
	}
	if fmt.Sprint(got) != "[Kernel panic - not syncing: x moved this boot]" {
		t.Fatalf("got %q", got)
	}
	if _, err := ReadPstoreArchive(filepath.Join(dir, "none"), boot, 1<<20); !os.IsNotExist(err) {
		t.Fatalf("missing dir: %v", err)
	}
}

func TestNotifyReady(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	notifyReady(NewLogger(io.Discard, 10))
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("got %q %v", buf[:n], err)
	}
}
