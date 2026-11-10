package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

func TestParseNetconsole(t *testing.T) {
	for in, want := range map[string]string{
		"6,123,4567,-;hello\n SUBSYSTEM=net\n": "6 123 4567 hello",
		"6.12.1,3,9,10,c;with release":         "3 9 10 with release",
		"0,7,1,-,ncfrag=0/10;first":            "0 7 1 first",
	} {
		head, _, body, err := parseNetconsole([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		l := toLine("h", head, body)
		if got := fmt.Sprint(l.priority, " ", l.seq, " ", l.tsUsec, " ", l.msg); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"plain netconsole line", "6,x,1,-;m", "6,1,1;m", "6,1,1,-,ncfrag=9/5;m"} {
		if _, _, _, err := parseNetconsole([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseNetconsoleHosts(t *testing.T) {
	h, err := ParseNetconsoleHosts(strings.NewReader("# hosts\n10.0.0.7 node-1\n::ffff:10.0.0.8 node-2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Lookup(netip.MustParseAddr("10.0.0.7")) != "node-1" || h.Lookup(netip.MustParseAddr("10.0.0.8")) != "node-2" || h.Lookup(netip.MustParseAddr("10.0.0.9")) != "" {
		t.Fatal("lookup")
	}
	for _, bad := range []string{"10.0.0.7", "nope node", "10.0.0.7 bad host"} {
		if _, err := ParseNetconsoleHosts(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNetconsolePanicWithoutAgent(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.in.NetconsoleDelay = 0
	hosts, _ := ParseNetconsoleHosts(strings.NewReader("10.0.0.7 node-1\n"))
	nc := &Netconsole{In: e.in, From: mustPrefixes(t, "10.0.0.0/24"), frags: map[string]*ncFrag{}}
	nc.Hosts.Store(hosts)
	from := &net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 6666}
	send := func(s string) { nc.Handle([]byte(s), from, time.Now()) }

	// The agent of boot A sends a line, and netconsole sends the same one: it is stored once.
	e.send(t, kmsgPkt(0xa, 1, 1, 5, 500, "hello"))
	e.waitRecords(t, 1)
	send("6,5,500,-;hello")
	// The panic only comes through netconsole, in two fragments.
	send("0,6,60000000,-,ncfrag=0/43;Kernel panic - not ")
	send("0,6,60000000,-,ncfrag=19/43;syncing: Fatal exception")
	recs := e.waitRecords(t, 2)
	p := recs[1]
	if p.Source != "netconsole" || p.Message != "Kernel panic - not syncing: Fatal exception" || p.BootID != wire.FormatBootID([16]byte{0xa}) || p.Level != 0 {
		t.Fatalf("panic record %+v", p)
	}
	// Lines from unknown senders and lines of a new boot not known yet are dropped.
	nc.Handle([]byte("6,7,700,-;spoofed"), &net.UDPAddr{IP: net.ParseIP("10.0.1.7"), Port: 1}, time.Now())
	send("6,0,1,-;Linux version of the next boot")
	send("plain line")

	// The next boot starts: the netconsole panic line makes it a crash, without pstore.
	e.send(t, kmsgPkt(0xb, 2, 1, 0, 1, "booting"))
	e.waitRecords(t, 3)
	e.det.Tick(context.Background(), time.Now().Add(time.Second))
	l, _ := e.st.Incidents(context.Background(), store.IncidentFilter{Kind: "crash"})
	if len(l) != 1 || l[0].Rule != "panic" || l[0].BootID != wire.FormatBootID([16]byte{0xa}) {
		t.Fatalf("crash incidents %+v", l)
	}
	m := e.get(t, "/metrics")
	for _, want := range []string{
		`lastgasp_records_deduplicated_total{host="node-1",source="netconsole"} 1`,
		`lastgasp_records_stored_total{host="node-1",source="netconsole"} 1`,
		`lastgasp_packets_invalid_total{reason="netconsole_source"} 1`,
		`lastgasp_packets_invalid_total{reason="netconsole_boot"} 1`,
		`lastgasp_packets_invalid_total{reason="netconsole_format"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestPstoreLineMatchesNetconsole(t *testing.T) {
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	e.in.NetconsoleDelay = 0
	hosts, _ := ParseNetconsoleHosts(strings.NewReader("10.0.0.7 node-1\n"))
	nc := &Netconsole{In: e.in, From: mustPrefixes(t, "10.0.0.7"), frags: map[string]*ncFrag{}}
	nc.Hosts.Store(hosts)
	e.send(t, kmsgPkt(0xa, 1, 1, 5, 500, "hello"))
	e.waitRecords(t, 1)
	nc.Handle([]byte("0,6,600,-;Kernel panic"), &net.UDPAddr{IP: net.ParseIP("10.0.0.7")}, time.Now())
	e.waitRecords(t, 2)
	// The next boot sends the same panic line from pstore: it is already there.
	e.send(t, &wire.Packet{Host: "node-1", BootID: [16]byte{0xb}, Instance: 2, Seq: 1, Kind: wire.KindPstore,
		Record: wire.Record{Priority: 0, Seq: 0, TsUsec: 600, FileID: 9, Part: 1, Parts: 1, Msg: "Kernel panic"}})
	e.send(t, kmsgPkt(0xb, 2, 2, 0, 1, "marker"))
	e.waitRecords(t, 3)
	if m := e.get(t, "/metrics"); !strings.Contains(m, `lastgasp_records_deduplicated_total{host="node-1",source="pstore"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func mustPrefixes(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
