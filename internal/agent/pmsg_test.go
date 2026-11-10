package agent

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lastgasp/internal/wire"
)

func TestSenderSavesUnconfirmedToPmsg(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmsg0")
	os.WriteFile(path, nil, 0o600) // stands in for the device, which SavePmsg never creates
	q := NewQueue(10)
	q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 3, Seq: 7, TsUsec: 1500, Part: 1, Parts: 1, Msg: "disk error"}})
	q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 4, Seq: 8, TsUsec: 1600, Part: 2, Parts: 2, Msg: "tail of a \\x0a long line"}})
	first := NewQueue(2)
	first.Push(Item{Kind: wire.KindPstore, Rec: wire.Record{Msg: "already in pstore"}})
	// No server ever answers, which is when pmsg matters most.
	s := &Sender{Host: "h", Key: testKey, Queue: q, First: first, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: net.IPv4(127, 0, 0, 1), Port: 1}}, Heartbeat: 20 * time.Millisecond, WaitAck: true,
		PmsgPath: path, PmsgMax: 4096}
	s.newConn = func() (packetConn, error) { return &flakyConn{}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.Run(ctx)

	data, _ := os.ReadFile(path)
	lines := ParsePstore(data)
	if len(lines) != 2 {
		t.Fatalf("pmsg holds %q", data)
	}
	a, b := lines[0], lines[1]
	if a.Msg != "disk error" || a.Priority != 3 || a.TsUsec != 1500 || a.Seq != 7 || a.Part != 1 || a.Parts != 1 {
		t.Fatalf("line 0: %+v", a)
	}
	if b.Msg != "tail of a \\x0a long line" || b.Part != 2 || b.Parts != 2 {
		t.Fatalf("line 1: %+v", b)
	}
}

func TestSavePmsgKeepsNewestWithinLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmsg0")
	os.WriteFile(path, nil, 0o600)
	var items []Item
	for i := range 10 {
		items = append(items, Item{Kind: wire.KindKmsg, Rec: wire.Record{Seq: uint64(i), Part: 1, Parts: 1, Msg: strings.Repeat("x", 50)}})
	}
	one := len(formatPmsg(items[0]))
	if n, err := SavePmsg(path, items, 3*one+1); err != nil || n != 3 {
		t.Fatalf("saved %d, err %v", n, err)
	}
	lines := ParsePstore(func() []byte { b, _ := os.ReadFile(path); return b }())
	if len(lines) != 3 || lines[0].Seq != 7 || lines[2].Seq != 9 {
		t.Fatalf("lines %+v", lines)
	}
	// A kernel without pmsg has no device, and nothing is created in its place.
	if _, err := SavePmsg(filepath.Join(t.TempDir(), "none"), items, 4096); !os.IsNotExist(err) {
		t.Fatalf("missing device: %v", err)
	}
}

func TestParsePmsgRefusesOtherLines(t *testing.T) {
	for _, l := range []string{"LGPM1 x 1 2 1/1 m", "LGPM1 3 1 2 0/1 m", "LGPM1 3 1 2 2/1 m", "LGPM1 3 1", "an app line"} {
		if _, _, _, ok := parsePmsg(l); ok {
			t.Errorf("%q accepted", l)
		}
	}
}
