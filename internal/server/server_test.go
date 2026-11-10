package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"lastgasp/internal/agent"
	"lastgasp/internal/incident"
	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

var testKey = bytes.Repeat([]byte{1}, 32)

func pkt(host string, boot byte, inst, seq uint64) *wire.Packet {
	return &wire.Packet{Host: host, BootID: [16]byte{boot}, Instance: inst, Seq: seq, Kind: wire.KindHeartbeat}
}

func TestTrackerGapsLateAndDuplicates(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	for _, seq := range []uint64{1, 2, 6, 4, 4, 2, 10} {
		tr.Observe(pkt("h", 1, 1, seq), now)
	}
	s := tr.Snapshot()[0]
	// Missing after all packets: 3, 5, 7-9. 4 arrived late; 4 and 2 were duplicates.
	if s.Gaps != 6 || s.Recovered != 1 || s.Missing() != 5 || s.Duplicates != 2 || s.Received != 5 || s.MaxSeq != 10 {
		t.Fatalf("got %+v", s)
	}
	want := []Range{{3, 3}, {5, 5}, {7, 9}}
	if len(s.MissingSet) != 3 || s.MissingSet[0] != want[0] || s.MissingSet[1] != want[1] || s.MissingSet[2] != want[2] {
		t.Fatalf("ranges %v", s.MissingSet)
	}
	// Recovering the middle of a range splits it.
	tr.Observe(pkt("h", 1, 1, 8), now)
	s = tr.Snapshot()[0]
	if len(s.MissingSet) != 4 || s.MissingSet[2] != (Range{7, 7}) || s.MissingSet[3] != (Range{9, 9}) {
		t.Fatalf("ranges %v", s.MissingSet)
	}
}

func TestTrackerStreamsAreSeparate(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	tr.Observe(pkt("h", 1, 1, 1), now)
	tr.Observe(pkt("h", 1, 2, 1), now) // agent restarted
	tr.Observe(pkt("h", 2, 3, 3), now) // new boot, first two packets lost
	hosts := tr.Hosts(now, time.Minute)
	if len(hosts) != 1 || hosts[0].Streams != 3 || hosts[0].Missing != 2 || hosts[0].Received != 3 || !hosts[0].Up {
		t.Fatalf("got %+v", hosts)
	}
	if tr.Hosts(now.Add(time.Hour), time.Minute)[0].Up {
		t.Fatal("host should be down after staleAfter")
	}
}

func TestTrackerCapsRanges(t *testing.T) {
	tr := NewTracker()
	tr.maxRanges = 3
	for seq := uint64(1); seq <= 20; seq += 2 {
		tr.Observe(pkt("h", 1, 1, seq), time.Now())
	}
	s := tr.Snapshot()[0]
	if len(s.MissingSet) != 3 || s.Missing() != 9 {
		t.Fatalf("got %d ranges, missing %d", len(s.MissingSet), s.Missing())
	}
}

func TestKeyring(t *testing.T) {
	k, err := ParseKeyring(strings.NewReader("# comment\n\nnode-1 " + strings.Repeat("aa", 16) + "\n* " + strings.Repeat("bb", 16) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if k.Lookup("node-1")[0] != 0xaa || k.Lookup("other")[0] != 0xbb {
		t.Fatal("wrong key")
	}
	k, _ = ParseKeyring(strings.NewReader("node-1 " + strings.Repeat("aa", 16)))
	if k.Lookup("other") != nil {
		t.Fatal("host without key must be rejected when there is no default")
	}
	// An empty file, or one with comments only, holds no keys: only enrolled agents get in.
	for _, empty := range []string{"", "# keys come later\n\n"} {
		k, err := ParseKeyring(strings.NewReader(empty))
		if err != nil || k.Lookup("node-1") != nil {
			t.Fatalf("%q: %v", empty, err)
		}
	}
	for _, bad := range []string{"node-1", "node-1 short", "a b c"} {
		if _, err := ParseKeyring(strings.NewReader(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

type env struct {
	st      *store.Store
	tr      *Tracker
	in      *Ingestor
	det     *incident.Detector
	metrics *Metrics
	reg     *prometheus.Registry
	http    *httptest.Server
	dbPath  string
	cancel  context.CancelFunc
	stopped chan struct{}
}

func newEnv(t *testing.T, dbPath string) *env {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTracker()
	if err := LoadStreams(context.Background(), st, tr); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	keys, _ := ParseKeyring(strings.NewReader("* " + strings.Repeat("01", 32)))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewMetrics(reg, tr, time.Minute)
	in := NewIngestor(st, tr, keys, m, log)
	in.Detector = incident.NewDetector(st, incident.DefaultRules(), incident.Config{SilentAfter: time.Hour, CrashWait: 0, Context: 50},
		incident.NewMetrics(reg), log)
	ctx, cancel := context.WithCancel(context.Background())
	e := &env{st: st, tr: tr, in: in, det: in.Detector, metrics: m, reg: reg, dbPath: dbPath, cancel: cancel, stopped: make(chan struct{})}
	go func() { in.Run(ctx); close(e.stopped) }()
	e.http = httptest.NewServer((&API{Store: st, Tracker: tr, StaleAfter: time.Minute, Gatherer: reg, Context: 50}).Handler())
	t.Cleanup(e.stop)
	return e
}

func (e *env) stop() {
	e.cancel()
	<-e.stopped
	e.http.Close()
	e.st.Close()
}

func (e *env) send(t *testing.T, p *wire.Packet) {
	t.Helper()
	b, err := wire.Encode(p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	e.in.Handle(b, nil)
}

func (e *env) waitRecords(t *testing.T, want int) []store.Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		recs, err := e.st.Query(context.Background(), store.Filter{MaxLevel: -1, Oldest: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) >= want || time.Now().After(deadline) {
			if len(recs) != want {
				t.Fatalf("got %d records, want %d", len(recs), want)
			}
			return recs
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) get(t *testing.T, path string) string {
	t.Helper()
	resp, err := http.Get(e.http.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
	}
	return string(b)
}

func kmsgPkt(boot byte, inst, seq, kseq uint64, ts uint64, msg string) *wire.Packet {
	return &wire.Packet{Host: "node-1", BootID: [16]byte{boot}, Instance: inst, Seq: seq, Kind: wire.KindKmsg,
		Record: wire.Record{Priority: 3, Seq: kseq, TsUsec: ts, Part: 1, Parts: 1, Msg: msg}}
}

func TestDedupAcrossRestartsAndPstore(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	// Boot A: two kernel lines, then the machine crashes.
	e.send(t, kmsgPkt(0xa, 1, 1, 0, 100, "booting"))
	e.send(t, kmsgPkt(0xa, 1, 2, 1, 200, "disk error"))
	e.waitRecords(t, 2)
	// The agent restarts in the same boot and replays the kernel buffer.
	e.send(t, kmsgPkt(0xa, 2, 1, 0, 100, "booting"))
	e.send(t, kmsgPkt(0xa, 2, 2, 1, 200, "disk error"))
	e.send(t, kmsgPkt(0xa, 2, 3, 2, 300, "new line"))
	e.waitRecords(t, 3)

	// Boot B: pstore holds the tail of boot A, including a line that never made it out.
	pstore := func(seq, line, ts uint64, msg string) *wire.Packet {
		return &wire.Packet{Host: "node-1", BootID: [16]byte{0xb}, Instance: 3, Seq: seq, Kind: wire.KindPstore,
			Record: wire.Record{Priority: 0, Seq: line, TsUsec: ts, FileID: 77, Part: 1, Parts: 1, Msg: msg}}
	}
	e.send(t, pstore(1, 0, 200, "disk error"))
	e.send(t, pstore(2, 1, 300, "new line"))
	e.send(t, pstore(3, 2, 400, "Kernel panic"))
	recs := e.waitRecords(t, 4)
	last := recs[3]
	if last.Message != "Kernel panic" || last.Source != "pstore" || last.BootID != wire.FormatBootID([16]byte{0xa}) {
		t.Fatalf("pstore record not attributed to boot A: %+v", last)
	}
	// pstore is not cleared, so the next boot sends the same file again.
	e.send(t, pstore(1, 2, 400, "Kernel panic"))
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xc}, Instance: 4, Seq: 1, Kind: wire.KindPstore,
		Record: wire.Record{Seq: 2, TsUsec: 400, FileID: 77, Part: 1, Parts: 1, Msg: "Kernel panic"}})
	e.send(t, kmsgPkt(0xc, 4, 2, 0, 1, "marker"))
	e.waitRecords(t, 5)

	metrics := e.get(t, "/metrics")
	for _, want := range []string{
		`lastgasp_records_deduplicated_total{host="node-1",source="kmsg"} 2`,
		`lastgasp_records_deduplicated_total{host="node-1",source="pstore"} 3`,
		`lastgasp_packets_duplicate_total{host="node-1"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestMultiLinePstoreMatchesKmsg(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	// Boot A sends a two-line record as /dev/kmsg shows it, then crashes.
	k, err := agent.ParseKmsg([]byte("4,7,2000000,-;WARNING: at foo\\x0a\\x09bar+0x10\n"))
	if err != nil {
		t.Fatal(err)
	}
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xa}, Instance: 1, Seq: 1, Kind: wire.KindKmsg,
		Record: wire.Record{Priority: k.Priority, Seq: k.Seq, TsUsec: k.TsUsec, Part: 1, Parts: 1, Msg: k.Msg}})
	e.waitRecords(t, 1)
	// Boot B finds the same record in pstore, written as two lines with the same prefix.
	for i, l := range agent.ParsePstore([]byte("<4>[    2.000000] WARNING: at foo\n<4>[    2.000000] \tbar+0x10\n")) {
		e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xb}, Instance: 2, Seq: uint64(i + 1), Kind: wire.KindPstore,
			Record: wire.Record{Priority: l.Priority, Seq: l.Line, TsUsec: l.TsUsec, FileID: l.FileID, Part: 1, Parts: 1, Msg: l.Msg}})
	}
	e.send(t, kmsgPkt(0xb, 2, 9, 0, 1, "marker"))
	if recs := e.waitRecords(t, 2); recs[0].Source != "kmsg" || recs[1].Message != "marker" {
		t.Fatalf("records %+v", recs)
	}
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_records_deduplicated_total{host="node-1",source="pstore"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestPmsgRecordsMatchKmsg(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	// Boot A: the second part of a long record arrives, the next record does not.
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xa}, Instance: 1, Seq: 1, Kind: wire.KindKmsg,
		Record: wire.Record{Priority: 4, Seq: 7, TsUsec: 900, Part: 2, Parts: 2, Msg: "second half"}})
	e.waitRecords(t, 1)
	// The agent saved both to pmsg when it stopped. Boot B sends them from pstore.
	path := filepath.Join(t.TempDir(), "pmsg0")
	os.WriteFile(path, nil, 0o600)
	items := []agent.Item{
		{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 4, Seq: 7, TsUsec: 900, Part: 2, Parts: 2, Msg: "second half"}},
		{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 0, Seq: 8, TsUsec: 950, Part: 1, Parts: 1, Msg: "never arrived"}},
	}
	if _, err := agent.SavePmsg(path, items, 4096); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for i, l := range agent.ParsePstore(data) {
		e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xb}, Instance: 2, Seq: uint64(i + 1), Kind: wire.KindPstore,
			Record: wire.Record{Priority: l.Priority, Seq: l.Line, TsUsec: l.TsUsec, FileID: l.FileID, Part: l.Part, Parts: l.Parts, Msg: l.Msg}})
	}
	recs := e.waitRecords(t, 2)
	if recs[1].Message != "never arrived" || recs[1].Source != "pstore" || recs[1].BootID != wire.FormatBootID([16]byte{0xa}) {
		t.Fatalf("records %+v", recs)
	}
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_records_deduplicated_total{host="node-1",source="pstore"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestJournalLines(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	journal := func(inst, seq, id uint64, msg string) *wire.Packet {
		return &wire.Packet{Host: "node-1", BootID: [16]byte{0xa}, Instance: inst, Seq: seq, Kind: wire.KindJournal,
			Record: wire.Record{Priority: 3<<3 | 4, TsUsec: 5, FileID: id, Part: 1, Parts: 1, Msg: msg}}
	}
	e.send(t, journal(1, 1, 0xabc, "systemd-coredump: Process 812 (nginx) of user 33 dumped core."))
	// After an agent restart the journal is read from the start of the boot again: the line is stored once.
	e.send(t, journal(2, 1, 0xabc, "systemd-coredump: Process 812 (nginx) of user 33 dumped core."))
	e.send(t, journal(2, 2, 0xabd, "app: fine"))
	recs := e.waitRecords(t, 2)
	if recs[0].Source != "journal" || recs[0].Level != 4 || recs[0].Facility != 3 {
		t.Fatalf("records %+v", recs)
	}
	l, _ := e.st.Incidents(context.Background(), store.IncidentFilter{Kind: incident.KindJournalError})
	if len(l) != 1 || l[0].Rule != "coredump" {
		t.Fatalf("incidents %+v", l)
	}
	var v IncidentView
	json.Unmarshal([]byte(e.get(t, "/api/incidents/"+strconv.FormatInt(l[0].ID, 10))), &v)
	if len(v.Records) != 1 || v.Records[0].Source != "journal" {
		t.Fatalf("view %+v", v.Records)
	}
}

func TestBadPacketsAreCounted(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	b, _ := wire.Encode(kmsgPkt(1, 1, 1, 0, 0, "x"), bytes.Repeat([]byte{2}, 32))
	e.in.Handle(b, nil)
	e.in.Handle([]byte("garbage"), nil)
	m := e.get(t, "/metrics")
	if !strings.Contains(m, `lastgasp_packets_invalid_total{reason="auth_failed"} 1`) ||
		!strings.Contains(m, `lastgasp_packets_invalid_total{reason="malformed"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

// replies collects acks sent after storing.
type replies struct {
	mu   sync.Mutex
	acks [][]byte
}

func (r *replies) add(b []byte, _ net.Addr) {
	r.mu.Lock()
	r.acks = append(r.acks, b)
	r.mu.Unlock()
}

// wait returns the next ack, decoded for the run of p.
func (r *replies) wait(t *testing.T, p *wire.Packet) wire.Ack {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		r.mu.Lock()
		var b []byte
		if len(r.acks) > 0 {
			b, r.acks = r.acks[0], r.acks[1:]
		}
		r.mu.Unlock()
		if b != nil {
			ack, err := wire.DecodeAck(b, testKey, p.Host, p.BootID, p.Instance)
			if err != nil {
				t.Fatal(err)
			}
			return ack
		}
	}
	t.Fatal("no ack")
	return wire.Ack{}
}

func TestHeartbeatsGetAcksAndProbesAreNotCounted(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	r := &replies{}
	e.in.SetReply(r.add)
	handle := func(p *wire.Packet) []byte {
		b, err := wire.Encode(p, testKey)
		if err != nil {
			t.Fatal(err)
		}
		return e.in.Handle(b, nil)
	}
	probe := pkt("node-1", 1, 1, 0)
	ack := handle(probe)
	if a, err := wire.DecodeAck(ack, testKey, "node-1", probe.BootID, 1); err != nil || a.Seq != 0 || a.Upto != 0 {
		t.Fatalf("probe ack %+v err %v", a, err)
	}
	if handle(kmsgPkt(1, 1, 1, 1, 1, "m")) != nil {
		t.Fatal("record packet got an ack")
	}
	// Acks per agent run are limited, so replayed heartbeats cannot be reflected at full rate.
	if handle(pkt("node-1", 1, 1, 0)) != nil {
		t.Fatal("second ack within the limit")
	}
	time.Sleep(ackEvery)
	// A heartbeat is answered once its batch is stored.
	beat := pkt("node-1", 1, 1, 2)
	if handle(beat) != nil {
		t.Fatal("heartbeat answered before it was stored")
	}
	if a := r.wait(t, beat); a.Seq != 2 || a.Upto != 2 || len(a.Missing) != 0 {
		t.Fatalf("heartbeat ack %+v", a)
	}
	e.waitRecords(t, 1)
	s := e.tr.Snapshot()
	if len(s) != 1 || s[0].Received != 2 || s[0].Duplicates != 0 || s[0].Missing() != 0 {
		t.Fatalf("streams %+v", s)
	}
}

func TestVersionTwoHeartbeatIsAnsweredAtOnce(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	p := pkt("node-1", 1, 1, 1)
	p.Version = 2
	b, _ := wire.Encode(p, testKey)
	ack := e.in.Handle(b, nil)
	if ack == nil || ack[4] != 2 {
		t.Fatal("version 2 heartbeat not answered with a version 2 ack")
	}
}

func TestAckTellsWhatArrived(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	r := &replies{}
	e.in.SetReply(r.add)
	// Packets 2 and 4 are lost.
	e.send(t, kmsgPkt(1, 1, 1, 1, 1, "a"))
	e.send(t, kmsgPkt(1, 1, 3, 3, 3, "c"))
	beat := pkt("node-1", 1, 1, 5)
	beat.Oldest = 1
	e.send(t, beat)
	if a := r.wait(t, beat); a.Upto != 5 || len(a.Missing) != 2 || a.Missing[0] != (wire.Range{From: 2, To: 2}) || a.Missing[1] != (wire.Range{From: 4, To: 4}) {
		t.Fatalf("ack %+v", a)
	}
	// 2 is sent again; 4 is no longer held by the agent, so it is given up.
	time.Sleep(ackEvery)
	e.send(t, kmsgPkt(1, 1, 2, 2, 2, "b"))
	beat = pkt("node-1", 1, 1, 6)
	beat.Oldest = 6
	e.send(t, beat)
	if a := r.wait(t, beat); a.Upto != 6 || len(a.Missing) != 0 {
		t.Fatalf("ack %+v", a)
	}
	e.waitRecords(t, 3)
	s := e.tr.Snapshot()[0]
	if s.Missing() != 1 || s.Recovered != 1 {
		t.Fatalf("stream %+v", s)
	}
}

func TestAckRangesFollowAgentVersion(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	r := &replies{}
	e.in.SetReply(r.add)
	// Each run loses every other packet, so it has more gaps than any ack holds.
	for inst, v := range map[uint64]string{1: "v0.1.5", 2: wire.WideAcksSince} {
		for seq := uint64(1); seq <= 2*wire.MaxAckRanges+10; seq += 2 {
			e.send(t, kmsgPkt(1, inst, seq, inst*1000+seq, seq, "m"))
		}
		beat := pkt("node-1", 1, inst, 2*wire.MaxAckRanges+20)
		beat.AgentVersion = v
		e.send(t, beat)
		if a := r.wait(t, beat); len(a.Missing) != wire.AckRanges(v) {
			t.Fatalf("agent %s got %d ranges", v, len(a.Missing))
		}
	}
}

func TestTrackerProgressAndForget(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	k := StreamKey{"h", wire.FormatBootID([16]byte{1}), 1}
	for seq := uint64(1); seq <= 2*wire.MaxAckRanges+10; seq += 2 {
		tr.Observe(pkt("h", 1, 1, seq), now)
	}
	// Only the first ranges fit an ack, and upto stops before the others.
	for _, limit := range []int{wire.LegacyAckRanges, wire.MaxAckRanges} {
		upto, missing := tr.Progress(k, limit)
		if len(missing) != limit || upto != missing[len(missing)-1].To+1 {
			t.Fatalf("limit %d: upto %d, %d ranges", limit, upto, len(missing))
		}
	}
	// A heartbeat says nothing below 20 can come again.
	beat := pkt("h", 1, 1, 2*wire.MaxAckRanges+20)
	beat.Oldest = 20
	tr.Observe(beat, now)
	if _, missing := tr.Progress(k, wire.MaxAckRanges); missing[0].From != 20 {
		t.Fatalf("ranges %v", missing)
	}
	if s := tr.Snapshot()[0]; s.Missing() != s.Gaps {
		t.Fatal("forgotten ranges must stay counted as missing")
	}
}

func TestTrackerUnreceive(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	for _, seq := range []uint64{1, 2, 3} {
		tr.Observe(pkt("h", 1, 1, seq), now)
	}
	tr.Unreceive(pkt("h", 1, 1, 2))
	tr.Unreceive(pkt("h", 1, 1, 2))
	s := tr.Snapshot()[0]
	if s.Missing() != 1 || s.Received != 2 || len(s.MissingSet) != 1 || s.MissingSet[0] != (Range{2, 2}) {
		t.Fatalf("stream %+v", s)
	}
	// Sent again, it counts as late, not as a duplicate.
	if !tr.Observe(pkt("h", 1, 1, 2), now) {
		t.Fatal("packet sent again refused")
	}
}

func TestGapsInAPIAndMetricsSurviveRestart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "db")
	e := newEnv(t, db)
	for _, seq := range []uint64{1, 2, 5} {
		e.send(t, kmsgPkt(1, 9, seq, seq, seq, "m"))
	}
	e.waitRecords(t, 3)

	var streams []Stream
	json.Unmarshal([]byte(e.get(t, "/api/streams")), &streams)
	if len(streams) != 1 || streams[0].Missing() != 2 || streams[0].MissingSet[0] != (Range{3, 4}) {
		t.Fatalf("streams %+v", streams)
	}
	var hosts []HostView
	json.Unmarshal([]byte(e.get(t, "/api/hosts")), &hosts)
	if len(hosts) != 1 || hosts[0].Missing != 2 || hosts[0].Boots != 1 {
		t.Fatalf("hosts %+v", hosts)
	}
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_packets_missing{host="node-1"} 2`) {
		t.Fatalf("metrics:\n%s", m)
	}
	e.stop()

	// After a server restart the state is loaded back and a late packet still counts as recovered.
	e2 := newEnv(t, db)
	e2.send(t, kmsgPkt(1, 9, 4, 4, 4, "late"))
	e2.send(t, kmsgPkt(1, 9, 6, 6, 6, "next"))
	e2.waitRecords(t, 5)
	m := e2.get(t, "/metrics")
	for _, want := range []string{`lastgasp_packets_missing{host="node-1"} 1`, `lastgasp_packets_late_total{host="node-1"} 1`} {
		if !strings.Contains(m, want) {
			t.Fatalf("metrics missing %s:\n%s", want, m)
		}
	}
}

func TestLogsAPIAndDownload(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.send(t, kmsgPkt(1, 1, 1, 1, 1, "first"))
	p := kmsgPkt(1, 1, 2, 2, 2, "second")
	p.Record.Priority = 6
	e.send(t, p)
	e.waitRecords(t, 2)

	var recs []store.Record
	json.Unmarshal([]byte(e.get(t, "/api/logs?level=3")), &recs)
	if len(recs) != 1 || recs[0].Message != "first" || recs[0].Level != 3 {
		t.Fatalf("got %+v", recs)
	}
	lines := strings.Split(strings.TrimSpace(e.get(t, "/api/download?host=node-1")), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"message":"first"`) {
		t.Fatalf("download: %v", lines)
	}
	if !strings.Contains(e.get(t, "/"), "<title>lastgasp</title>") {
		t.Fatal("ui not served")
	}
}

// TestAgentToServerOverUDP runs a real agent sender and the UDP listener.
func TestAgentToServerOverUDP(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.in.Listen(conn)
	defer conn.Close()

	res, err := agent.NewResolver([]string{conn.LocalAddr().String()}, "")
	if err != nil {
		t.Fatal(err)
	}
	q := agent.NewQueue(100)
	long := strings.Repeat("x", 3000)
	for i, msg := range []string{"hello", long} {
		parts := wire.SplitMessage(msg, wire.MaxMsg(len("node-1")))
		for j, part := range parts {
			q.Push(agent.Item{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 4, Seq: uint64(i), Part: uint8(j + 1), Parts: uint8(len(parts)), Msg: part}})
		}
	}
	s := &agent.Sender{Host: "node-1", Instance: 1, Key: testKey, Queue: q, Resolver: res,
		Stats: &agent.Stats{}, Log: agent.NewLogger(io.Discard, 10), Heartbeat: time.Hour, WaitAck: true}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer cancel()

	recs := e.waitRecords(t, 4)
	var joined string
	for _, r := range recs[1:] {
		joined += r.Message
	}
	if recs[0].Message != "hello" || joined != long || recs[1].Parts != 3 {
		t.Fatalf("records %+v", recs)
	}
	// The next heartbeat confirms every record, so the agent lets them go.
	for deadline := time.Now().Add(5 * time.Second); q.Len() > 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if q.Len() != 0 {
		t.Fatalf("%d records not confirmed", q.Len())
	}
}

// lossyProxy forwards UDP between one agent and the server, and drops the first packet that drop picks.
func lossyProxy(t *testing.T, server net.Addr, drop func([]byte) bool) net.Addr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65536)
		var agentAddr net.Addr
		dropped := false
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if from.String() == server.String() {
				if agentAddr != nil {
					conn.WriteTo(buf[:n], agentAddr)
				}
				continue
			}
			agentAddr = from
			if !dropped && drop(buf[:n]) {
				dropped = true
				continue
			}
			conn.WriteTo(buf[:n], server)
		}
	}()
	return conn.LocalAddr()
}

// TestAgentSendsLostRecordAgain loses one record on the way and checks that it still gets stored.
func TestAgentSendsLostRecordAgain(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.in.Listen(conn)
	defer conn.Close()
	proxy := lossyProxy(t, conn.LocalAddr(), func(b []byte) bool {
		p, err := wire.Decode(b, func(string) []byte { return testKey })
		return err == nil && p.Kind == wire.KindKmsg && p.Record.Msg == "lost once"
	})

	res, err := agent.NewResolver([]string{proxy.String()}, "")
	if err != nil {
		t.Fatal(err)
	}
	q := agent.NewQueue(100)
	for i, msg := range []string{"first", "lost once", "last"} {
		q.Push(agent.Item{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 4, Seq: uint64(i), Part: 1, Parts: 1, Msg: msg}})
	}
	s := &agent.Sender{Host: "node-1", Instance: 1, Key: testKey, Queue: q, Resolver: res,
		Stats: &agent.Stats{}, Log: agent.NewLogger(io.Discard, 10), Heartbeat: 300 * time.Millisecond, WaitAck: true}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	defer cancel()

	recs := e.waitRecords(t, 3)
	if recs[2].Message != "lost once" {
		t.Fatalf("records %+v", recs)
	}
	for deadline := time.Now().Add(5 * time.Second); q.Len() > 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	st := e.tr.Snapshot()[0]
	if q.Len() != 0 || st.Missing() != 0 || st.Recovered != 1 {
		t.Fatalf("queue %d, stream %+v", q.Len(), st)
	}
}

func TestKeyFileReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(path, []byte("node-1 "+strings.Repeat("aa", 16)+"\n"), 0o600)
	k, err := OpenKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if k.Lookup("node-2") != nil {
		t.Fatal("node-2 should be unknown")
	}
	os.WriteFile(path, []byte("node-1 "+strings.Repeat("aa", 16)+"\nnode-2 "+strings.Repeat("bb", 16)+"\n"), 0o600)
	if err := k.Reload(); err != nil {
		t.Fatal(err)
	}
	if k.Lookup("node-2")[0] != 0xbb || k.Hosts() != 2 {
		t.Fatal("reload did not add node-2")
	}
	// A broken file keeps the old keys.
	os.WriteFile(path, []byte("garbage\n"), 0o600)
	if err := k.Reload(); err == nil {
		t.Fatal("broken file accepted")
	}
	if k.Lookup("node-2") == nil {
		t.Fatal("old keys lost after a failed reload")
	}
}

func TestRetention(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.send(t, kmsgPkt(1, 1, 1, 1, 1, "old"))
	e.waitRecords(t, 1)
	e.in.saveStreams(context.Background())
	r := &Retention{Store: e.st, Tracker: e.tr, Detector: e.det, Metrics: e.metrics,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Age: time.Hour}
	if err := r.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	e.waitRecords(t, 1) // nothing is old yet
	if err := r.RunOnce(context.Background(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.waitRecords(t, 0)
	if len(e.tr.Snapshot()) != 0 {
		t.Fatal("stream not pruned")
	}
	if saved, _ := e.st.LoadStreams(context.Background()); len(saved) != 0 {
		t.Fatalf("saved streams left: %d", len(saved))
	}
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_retention_deleted_total{table="records"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestIncidentShowsLinesAfterAndLogsFilterByBoot(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.send(t, kmsgPkt(0xa, 1, 1, 0, 100, "before"))
	e.send(t, kmsgPkt(0xa, 1, 2, 1, 200, "BUG: unable to handle page fault"))
	for i := uint64(3); i <= 30; i++ {
		e.send(t, kmsgPkt(0xa, 1, i, i, i*100, fmt.Sprint("after ", i)))
	}
	e.send(t, kmsgPkt(0xb, 2, 1, 0, 100, "other boot"))
	e.waitRecords(t, 31)
	var list []store.Incident
	json.Unmarshal([]byte(e.get(t, "/api/incidents?kind=kernel_error")), &list)
	if len(list) != 1 {
		t.Fatalf("incidents %+v", list)
	}
	var v IncidentView
	json.Unmarshal([]byte(e.get(t, "/api/incidents/"+strconv.FormatInt(list[0].ID, 10))), &v)
	if len(v.Records) != 2 || len(v.After) != afterLines || v.After[0].Message != "after 3" {
		t.Fatalf("records %d, after %+v", len(v.Records), v.After)
	}
	var recs []store.Record
	json.Unmarshal([]byte(e.get(t, "/api/logs?boot="+wire.FormatBootID([16]byte{0xb}))), &recs)
	if len(recs) != 1 || recs[0].Message != "other boot" {
		t.Fatalf("boot filter: %+v", recs)
	}
}

// TestCrashIncidentEndToEnd sends a boot that dies with a panic, then the next boot with pstore lines.
func TestCrashIncidentEndToEnd(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.send(t, kmsgPkt(0xa, 1, 1, 0, 100, "booting"))
	e.send(t, kmsgPkt(0xa, 1, 2, 1, 200, "Kernel panic - not syncing: Fatal exception"))
	e.waitRecords(t, 2)
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xb}, Instance: 2, Seq: 1, Kind: wire.KindPstore,
		Record: wire.Record{Seq: 0, TsUsec: 300, FileID: 5, Part: 1, Parts: 1, Msg: "---[ end Kernel panic ]---"}})
	e.waitRecords(t, 3)
	e.det.Tick(context.Background(), time.Now())

	var list []struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
		Rule string `json:"rule"`
	}
	json.Unmarshal([]byte(e.get(t, "/api/incidents")), &list)
	if len(list) != 2 || list[0].Kind != "crash" || list[0].Rule != "panic" || list[1].Kind != "kernel_error" {
		t.Fatalf("incidents %+v", list)
	}
	var v IncidentView
	json.Unmarshal([]byte(e.get(t, "/api/incidents/"+strconv.FormatInt(list[0].ID, 10))), &v)
	if len(v.Records) != 2 || v.Records[1].Message != "Kernel panic - not syncing: Fatal exception" || len(v.Pstore) != 1 {
		t.Fatalf("view %+v", v)
	}

	ack := func(ct string) int {
		req, _ := http.NewRequest("POST", e.http.URL+"/api/incidents/"+strconv.FormatInt(list[0].ID, 10)+"/ack", strings.NewReader("{}"))
		req.Header.Set("Content-Type", ct)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := ack("application/x-www-form-urlencoded"); code != http.StatusUnsupportedMediaType {
		t.Fatalf("form ack got %d", code)
	}
	if code := ack("application/json"); code != 200 {
		t.Fatalf("ack got %d", code)
	}
	if resp, _ := http.Get(e.http.URL + "/api/incidents/999"); resp.StatusCode != 404 {
		t.Fatalf("unknown incident got %d", resp.StatusCode)
	}
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_incidents_total{host="node-1",kind="crash"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestMetricsSurviveBadHostLabel(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	// Older data or a bug could still put a bad name in the tracker; a scrape must not crash.
	e.tr.Observe(&wire.Packet{Host: "bad\xff", Seq: 1, Kind: wire.KindHeartbeat}, time.Now())
	e.send(t, kmsgPkt(1, 1, 1, 1, 1, "x"))
	e.waitRecords(t, 1)
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_packets_received_total{host="node-1"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":            "plain",
		"é ok":             "é ok",
		"a\x00b":           `a\x00b`,
		"bad\xff\xfe end":  `bad\xff\xfe end`,
		"cut \xe2\x82 end": `cut \xe2\x82 end`,
	} {
		if got := cleanText(in); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBinaryPstoreLineIsStored(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{2}, Instance: 1, Seq: 1, Kind: wire.KindPstore,
		Record: wire.Record{FileID: 1, Part: 1, Parts: 1, Msg: "garbage \x00\xff after crash"}})
	if recs := e.waitRecords(t, 1); recs[0].Message != `garbage \x00\xff after crash` {
		t.Fatalf("stored %q", recs[0].Message)
	}
}

// TestBootsInOneBatchKeepTheirOrder sends a crash and the next boot so fast that they share one batch.
func TestBootsInOneBatchKeepTheirOrder(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	fixed := time.Now()
	e.in.now = func() time.Time { return fixed }
	e.send(t, kmsgPkt(0xa, 1, 1, 0, 100, "Kernel panic - not syncing: x"))
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xb}, Instance: 2, Seq: 1, Kind: wire.KindPstore,
		Record: wire.Record{FileID: 3, Part: 1, Parts: 1, Msg: "pstore line"}})
	recs := e.waitRecords(t, 2)
	if recs[1].BootID != wire.FormatBootID([16]byte{0xa}) {
		t.Fatalf("pstore line given to boot %s", recs[1].BootID)
	}
	l, _ := e.st.Incidents(context.Background(), store.IncidentFilter{Kind: "reboot"})
	if len(l) != 1 {
		t.Fatalf("reboot not detected: %+v", l)
	}
}

// TestRetiredBootIsNoReboot replays a boot removed by retention, which must not look like a reboot.
func TestRetiredBootIsNoReboot(t *testing.T) {
	db := filepath.Join(t.TempDir(), "db")
	e := newEnv(t, db)
	e.send(t, kmsgPkt(0xa, 1, 1, 0, 100, "boot a"))
	e.waitRecords(t, 1)
	e.send(t, kmsgPkt(0xb, 2, 1, 0, 100, "boot b"))
	e.waitRecords(t, 2)
	r := &Retention{Store: e.st, Tracker: e.tr, Detector: e.det, Metrics: e.metrics,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Age: time.Hour}
	if err := r.RunOnce(context.Background(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.stop()

	// After a restart, an old packet of boot a arrives again.
	e2 := newEnv(t, db)
	e2.send(t, kmsgPkt(0xa, 3, 1, 0, 100, "boot a"))
	e2.waitRecords(t, 1)
	l, _ := e2.st.Incidents(context.Background(), store.IncidentFilter{Kind: "reboot"})
	if len(l) != 1 {
		t.Fatalf("got %d reboot incidents, want only the real one", len(l))
	}
	hosts, _ := e2.st.Hosts(context.Background())
	if hosts[0].LastBoot != wire.FormatBootID([16]byte{0xb}) {
		t.Fatalf("newest boot is %s", hosts[0].LastBoot)
	}
}

func TestUIHasControls(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	page := e.get(t, "/")
	for _, id := range []string{"inc-ack", "inc-copy", "inc-logs", "inc-msg", "inc-note", "inc-resolve", "inc-silence", "sil-add", "silences", "tok-add", "agents", "logout",
		"f-clear", "f-live", "more", "jump", "download"} {
		if !strings.Contains(page, `id="`+id+`"`) {
			t.Errorf("control %q missing", id)
		}
	}
	// The Clipboard API is missing on plain HTTP, so copy buttons need the fallback.
	if !strings.Contains(page, `execCommand("copy")`) || strings.Count(page, "navigator.clipboard") != 2 {
		t.Error("copy buttons must go through copyText, which works without HTTPS")
	}
}

// TestAgentRestartSendsStashedRecords runs an agent while no server answers, stops it, removes the
// pstore file, and checks that the next run still delivers the lines from the stash.
func TestAgentRestartSendsStashedRecords(t *testing.T) {
	shm, err := os.MkdirTemp("/dev/shm", "lastgasp-test-")
	if err != nil {
		t.Skip("no /dev/shm:", err)
	}
	defer os.RemoveAll(shm)
	dir := t.TempDir()
	bootFile, pstoreDir := filepath.Join(dir, "boot_id"), filepath.Join(dir, "pstore")
	os.WriteFile(bootFile, []byte("6f1c2a5e-0d4b-4e8a-9c3f-2b7d1e5a8c90\n"), 0o600)
	os.Mkdir(pstoreDir, 0o700)
	os.WriteFile(filepath.Join(pstoreDir, "dmesg-ramoops-0"), []byte("<0>[1.0] Kernel panic - not syncing\n<4>[1.1] last words\n"), 0o600)

	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	cfg := agent.Config{Servers: []string{silent.LocalAddr().String()}, Key: testKey, Host: "node-1", BootIDPath: bootFile,
		KmsgPath: filepath.Join(dir, "no-kmsg"), PstoreDir: pstoreDir, BufferSize: 100, Heartbeat: 100 * time.Millisecond,
		WaitAck: true, ResolveEvery: time.Minute, MaxPstoreFile: 1 << 20, StashPath: filepath.Join(shm, "agent.stash"), StashSize: agent.MinStash}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	agent.Run(ctx, cfg, agent.NewLogger(io.Discard, 100))
	cancel()
	// systemd-pstore moves the files away, so only the stash still has the lines.
	os.Remove(filepath.Join(pstoreDir, "dmesg-ramoops-0"))

	e := newEnv(t, filepath.Join(dir, "db"))
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.in.Listen(conn)
	defer conn.Close()
	cfg.Servers = []string{conn.LocalAddr().String()}
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { agent.Run(ctx, cfg, agent.NewLogger(io.Discard, 100)); close(done) }()
	recs := e.waitRecords(t, 2)
	cancel()
	<-done
	if recs[0].Source != "pstore" || recs[0].Message != "Kernel panic - not syncing" || recs[1].Message != "last words" {
		t.Fatalf("records %+v", recs)
	}
}

func TestRetentionRecordLimits(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	for i := uint64(1); i <= 5; i++ {
		p := kmsgPkt(1, 1, i, i, i, fmt.Sprint("line ", i))
		p.Record.Priority = 6
		if i == 1 {
			p.Record.Priority = 3
		}
		e.send(t, p)
	}
	e.waitRecords(t, 5)
	r := &Retention{Store: e.st, Tracker: e.tr, Metrics: e.metrics, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		InfoAge: time.Hour, MaxHostRecords: 3}
	if !r.Enabled() {
		t.Fatal("retention not enabled")
	}
	if err := r.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	recs := e.waitRecords(t, 3)
	if recs[0].Message != "line 3" {
		t.Fatalf("records %+v", recs)
	}
	// The host limit already removed the error, and two hours later the info lines are old enough to go.
	if err := r.RunOnce(context.Background(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.waitRecords(t, 0)
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_retention_deleted_total{table="records"} 5`) {
		t.Fatalf("metrics:\n%s", m)
	}
	if len(e.tr.Snapshot()) != 1 {
		t.Fatal("record limits must not prune agent runs")
	}
}

func TestRetentionByteLimit(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	for i := uint64(1); i <= 400; i++ {
		e.send(t, kmsgPkt(1, 1, i, i, i, fmt.Sprint(i, " ", strings.Repeat("x", 800))))
	}
	e.waitRecords(t, 400)
	size, _, err := e.st.RecordsSize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := &Retention{Store: e.st, Tracker: e.tr, Metrics: e.metrics, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBytes: size / 2}
	if err := r.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	all, _ := e.st.Query(context.Background(), store.Filter{MaxLevel: -1, Limit: 1000})
	if len(all) == 0 || len(all) > 200 || !strings.HasPrefix(all[0].Message, "400 ") {
		t.Fatalf("%d records left", len(all))
	}
	if after, _, _ := e.st.RecordsSize(context.Background()); after > size/2 {
		t.Fatalf("size %d, limit %d", after, size/2)
	}
	if m := e.get(t, "/metrics"); !strings.Contains(m, fmt.Sprintf(`lastgasp_retention_deleted_total{table="records"} %d`, 400-len(all))) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestParseSize(t *testing.T) {
	for v, want := range map[string]int64{"0": 0, "500": 500, "1K": 1 << 10, "2KiB": 2 << 10, "3MB": 3 << 20, "20GiB": 20 << 30, "1T": 1 << 40} {
		if got, err := ParseSize(v); err != nil || got != want {
			t.Errorf("%q: got %d %v, want %d", v, got, err, want)
		}
	}
	for _, v := range []string{"", "-1", "GiB", "1X", "1.5G", "99999999999T"} {
		if _, err := ParseSize(v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestSelfCheckOpensServerIncident(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	sc := &SelfCheck{Detector: e.det, Checks: ServerChecks(e.metrics, incident.NewMetrics(prometheus.NewRegistry()))}
	ctx := context.Background()
	sc.RunOnce(ctx, time.Now())
	b, _ := wire.Encode(kmsgPkt(1, 1, 1, 0, 0, "x"), bytes.Repeat([]byte{2}, 32))
	e.in.Handle(b, nil)
	e.in.Handle(b, nil)
	e.in.Handle([]byte("garbage"), nil) // random packets are not a key problem
	sc.RunOnce(ctx, time.Now())
	sc.RunOnce(ctx, time.Now())
	e.det.Flush(ctx)
	l, err := e.st.Incidents(ctx, store.IncidentFilter{Kind: incident.KindServer})
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].Rule != "keys" || l[0].Count != 2 || l[0].Host != incident.ServerHost {
		t.Fatalf("incidents %+v", l)
	}
}

func TestIncidentWorkflowAPI(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	api := &API{Store: e.st, Tracker: e.tr, StaleAfter: time.Minute, Gatherer: e.reg, Detector: e.det}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	call := func(method, path, body string, want int) string {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
		}
		return string(b)
	}
	e.send(t, kmsgPkt(1, 1, 1, 1, 1, "Out of memory: Killed process 7"))
	e.waitRecords(t, 1)
	e.det.Flush(context.Background())

	if b := call("POST", "/api/incidents/1/ack", `{"note":"looking at it"}`, 200); !strings.Contains(b, `"acked_by":"admin"`) ||
		!strings.Contains(b, `"note":"looking at it"`) {
		t.Fatalf("ack: %s", b)
	}
	call("POST", "/api/incidents/1/ack", ``, 200) // the body is optional
	if b := call("POST", "/api/incidents/1/resolve", `{"note":"memory limit raised"}`, 200); !strings.Contains(b, `"resolved":true`) ||
		!strings.Contains(b, `"closed_at"`) || !strings.Contains(b, `"note":"memory limit raised"`) {
		t.Fatalf("resolve: %s", b)
	}
	call("POST", "/api/incidents/99/resolve", `{}`, 404)

	call("POST", "/api/silences", `{"host":"node-*","kind":"nope","duration":"1h"}`, 400)
	call("POST", "/api/silences", `{"host":"node-*","duration":"-1h"}`, 400)
	b := call("POST", "/api/silences", `{"host":"node-*","kind":"reboot","duration":"1h","comment":"kernel update"}`, 201)
	var sl store.Silence
	json.Unmarshal([]byte(b), &sl)
	if sl.ID == 0 || sl.CreatedBy != "admin" || sl.EndsAt.Sub(sl.StartsAt) != time.Hour || sl.StartsAt.Location() != time.UTC {
		t.Fatalf("silence: %s", b)
	}
	if b := call("GET", "/api/silences", "", 200); !strings.Contains(b, "kernel update") {
		t.Fatalf("list: %s", b)
	}
	call("DELETE", "/api/silences/"+strconv.FormatInt(sl.ID, 10), "", 204)
	if b := call("GET", "/api/silences", "", 200); strings.TrimSpace(b) != "[]" {
		t.Fatalf("ended silence still active: %s", b)
	}
	if b := call("GET", "/api/silences?all=1", "", 200); !strings.Contains(b, "kernel update") {
		t.Fatalf("ended silence not listed with all=1: %s", b)
	}
}

func TestVersionsInAPIAndMetrics(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{1}, Instance: 1, Seq: 1, Kind: wire.KindHeartbeat, AgentVersion: "v9.8.7"})
	for deadline := time.Now().Add(5 * time.Second); len(e.tr.Snapshot()) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if b := e.get(t, "/api/hosts"); !strings.Contains(b, `"agent_version":"v9.8.7"`) {
		t.Fatalf("hosts: %s", b)
	}
	if b := e.get(t, "/api/me"); !strings.Contains(b, `"version":"dev`) {
		t.Fatalf("me: %s", b)
	}
	m := e.get(t, "/metrics")
	if !strings.Contains(m, `lastgasp_agent_info{host="node-1",version="v9.8.7"} 1`) || !strings.Contains(m, `lastgasp_build_info{goversion=`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestReadyz(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	dbDown := false
	api := &API{Store: e.st, Tracker: e.tr, Gatherer: e.reg, Ready: func(ctx context.Context) error {
		if dbDown {
			return errors.New("database: dial tcp db.internal:5432: password authentication failed for user lastgasp")
		}
		return e.in.Ready()
	}}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	status := func() (int, string) {
		resp, err := http.Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := status(); code != 503 || body != "not ready\n" {
		t.Fatalf("before listen: %d %s", code, body)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.in.Listen(conn)
	for deadline := time.Now().Add(2 * time.Second); !e.in.listening.Load() && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if code, body := status(); code != 200 {
		t.Fatalf("ready: %d %s", code, body)
	}
	dbDown = true
	if code, body := status(); code != 503 || body != "not ready\n" {
		t.Fatalf("db down: %d %s", code, body)
	}
	conn.Close()
}

func TestSecurityHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	secure(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	got := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(got, want) {
			t.Fatalf("csp %q lacks %q", got, want)
		}
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("framing allowed")
	}
}

// Gaps whose ranges were forgotten still list the stream, with an empty range list and not null.
func TestStreamsForgottenRangesAreEmptyList(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	tr.Observe(pkt("h", 1, 1, 1), now)
	tr.Observe(pkt("h", 1, 1, 5), now)
	p := pkt("h", 1, 1, 6)
	p.Oldest = 6
	tr.Observe(p, now)
	if s := tr.Snapshot()[0]; s.Missing() == 0 || s.MissingSet != nil {
		t.Fatalf("setup: stream %+v", s)
	}
	rec := httptest.NewRecorder()
	(&API{Tracker: tr}).streams(rec, httptest.NewRequest("GET", "/api/streams", nil))
	if body := rec.Body.String(); !strings.Contains(body, `"missing_ranges":[]`) {
		t.Fatalf("body %s", body)
	}
}
