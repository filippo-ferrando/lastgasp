package agent

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lastgasp/internal/wire"
)

func TestParseJournal(t *testing.T) {
	e, id, cursor, ok := parseJournal([]byte(`{"__CURSOR":"s=1;i=2","PRIORITY":"3","SYSLOG_FACILITY":"4",` +
		`"_SYSTEMD_UNIT":"sshd.service","MESSAGE":"bad\tlogin","__MONOTONIC_TIMESTAMP":"1234"}`))
	if !ok || cursor != "s=1;i=2" || id == 0 || e.Priority != 4<<3|3 || e.TsUsec != 1234 || e.Msg != `sshd.service: bad\x09login` {
		t.Fatalf("got %+v %x %q %v", e, id, cursor, ok)
	}
	// The program name comes first: PID 1 logs as init.scope.
	e, _, _, ok = parseJournal([]byte(`{"__CURSOR":"c","MESSAGE":"x.service: Failed with result 'exit-code'.",` +
		`"SYSLOG_IDENTIFIER":"systemd","_SYSTEMD_UNIT":"init.scope"}`))
	if !ok || e.Msg != "systemd: x.service: Failed with result 'exit-code'." {
		t.Fatalf("got %+v %x %q %v", e, id, cursor, ok)
	}
	// A message that is not UTF-8 comes as an array of bytes. Without a unit, the program name is used.
	e, _, _, ok = parseJournal([]byte(`{"__CURSOR":"c2","MESSAGE":[104,105,255],"SYSLOG_IDENTIFIER":"app"}`))
	if !ok || e.Msg != `app: hi\xff` || e.Priority != 3<<3|6 {
		t.Fatalf("bytes: %+v", e)
	}
	// Kernel lines come from kmsg already, but their cursor still counts as read.
	e, _, _, _ = parseJournal([]byte(`{"__CURSOR":"c4","MESSAGE":"m","_SYSTEMD_UNIT":"user@1000.service","_SYSTEMD_USER_UNIT":"app.service"}`))
	if e.Msg != "app.service: m" {
		t.Fatalf("user unit: %q", e.Msg)
	}
	if _, _, cursor, ok := parseJournal([]byte(`{"__CURSOR":"c3","MESSAGE":"x","_TRANSPORT":"kernel"}`)); ok || cursor != "c3" {
		t.Fatal("kernel line taken")
	}
	if _, _, _, ok := parseJournal([]byte(`not json`)); ok {
		t.Fatal("garbage taken")
	}
}

// fakeJournalctl writes a script that logs its arguments and prints lines, like journalctl would.
func fakeJournalctl(t *testing.T, lines ...string) (cmd, argsLog string) {
	dir := t.TempDir()
	argsLog = filepath.Join(dir, "args")
	out := filepath.Join(dir, "out")
	os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	cmd = filepath.Join(dir, "journalctl")
	os.WriteFile(cmd, []byte("#!/bin/sh\necho \"$@\" >> "+argsLog+"\ncat "+out+"\n"), 0o700)
	return cmd, argsLog
}

func TestJournalReaderGoesOnFromCursor(t *testing.T) {
	cmd, argsLog := fakeJournalctl(t,
		`{"__CURSOR":"a","MESSAGE":"one","_COMM":"x"}`,
		`{"__CURSOR":"b","MESSAGE":"two","_COMM":"x"}`,
		`{"__CURSOR":"c","MESSAGE":"three","_COMM":"x"}`)
	var got []string
	j := &JournalReader{Command: cmd, Priority: 4, Rate: 2, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Push: func(e Entry, id uint64) { got = append(got, e.Msg) }}
	for range 2 {
		if err := j.follow(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// The rate limit lets 2 lines a second through, the third is counted as dropped.
	if strings.Join(got, ",") != "x: one,x: two,x: one,x: two" || j.Stats.BufferDrops.Load() != 2 {
		t.Fatalf("got %v, drops %d", got, j.Stats.BufferDrops.Load())
	}
	args, _ := os.ReadFile(argsLog)
	runs := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(runs) != 2 || strings.Contains(runs[0], "--after-cursor") || !strings.Contains(runs[0], "--priority=0..4") ||
		!strings.HasSuffix(runs[1], "--after-cursor=c") {
		t.Fatalf("journalctl runs: %q", runs)
	}
}

func TestSenderSendsJournalAfterKernelLines(t *testing.T) {
	conn := &flakyConn{}
	q, jq := NewQueue(4), NewQueue(4)
	jq.Push(Item{Kind: wire.KindJournal, Rec: wire.Record{FileID: 9, Part: 1, Parts: 1, Msg: "app: hi"}})
	q.Push(Item{Kind: wire.KindKmsg, Rec: wire.Record{Part: 1, Parts: 1, Msg: "kernel"}})
	s := &Sender{Host: "h", Key: testKey, Queue: q, Journal: jq, Stats: &Stats{}, Log: NewLogger(io.Discard, 10),
		Resolver: staticAddrs{{IP: []byte{127, 0, 0, 1}, Port: 1}}}
	s.newConn = func() (packetConn, error) { return conn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() {
		for (q.Len() > 0 || jq.Len() > 0) && ctx.Err() == nil {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	s.Run(ctx)
	var kinds []wire.Kind
	for _, b := range conn.sent {
		p, err := wire.Decode(b, func(string) []byte { return testKey })
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, p.Kind)
	}
	if len(kinds) != 2 || kinds[0] != wire.KindKmsg || kinds[1] != wire.KindJournal {
		t.Fatalf("sent %v", kinds)
	}
}
