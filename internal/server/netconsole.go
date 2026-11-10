package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"lastgasp/internal/wire"
)

// ncLine is one kernel record received with extended netconsole.
type ncLine struct {
	host     string
	priority uint16
	seq      uint64
	tsUsec   uint64
	msg      string
}

// ncFrag is a record cut into fragments by the kernel ("ncfrag=offset/total"), waiting for the rest.
type ncFrag struct {
	body  []byte
	got   int
	first time.Time
}

var errNetconsoleFormat = errors.New("netconsole: not an extended netconsole record")

// parseNetconsole reads "[release,]prio,seq,ts,flags[,ncfrag=off/len];message". Plain netconsole lines
// have no sequence number, so they cannot be matched with the agent copy and are refused.
func parseNetconsole(b []byte) (head []string, frag [2]int, body []byte, err error) {
	semi := bytes.IndexByte(b, ';')
	if semi < 0 {
		return nil, frag, nil, errNetconsoleFormat
	}
	fields := strings.Split(string(b[:semi]), ",")
	// With the "r" option the kernel release comes first.
	if len(fields) > 0 && strings.Contains(fields[0], ".") {
		fields = fields[1:]
	}
	if len(fields) < 4 {
		return nil, frag, nil, errNetconsoleFormat
	}
	for _, f := range fields[:3] {
		if _, err := strconv.ParseUint(f, 10, 64); err != nil {
			return nil, frag, nil, errNetconsoleFormat
		}
	}
	frag = [2]int{-1, 0}
	for _, f := range fields[4:] {
		if v, ok := strings.CutPrefix(f, "ncfrag="); ok {
			a, c, _ := strings.Cut(v, "/")
			off, err1 := strconv.Atoi(a)
			total, err2 := strconv.Atoi(c)
			if err1 != nil || err2 != nil || off < 0 || total <= 0 || total > 1<<16 || off >= total {
				return nil, frag, nil, errNetconsoleFormat
			}
			frag = [2]int{off, total}
		}
	}
	return fields[:3], frag, b[semi+1:], nil
}

// toLine finishes a record: the text ends at the first newline, as key=value lines follow it.
func toLine(host string, head []string, body []byte) ncLine {
	prio, _ := strconv.ParseUint(head[0], 10, 16)
	seq, _ := strconv.ParseUint(head[1], 10, 64)
	ts, _ := strconv.ParseUint(head[2], 10, 64)
	if nl := bytes.IndexByte(body, '\n'); nl >= 0 {
		body = body[:nl]
	}
	return ncLine{host: host, priority: uint16(prio), seq: seq, tsUsec: ts, msg: string(body)}
}

// NetconsoleHosts maps source addresses to host names, from "ip host" lines.
type NetconsoleHosts struct{ m map[netip.Addr]string }

// ParseNetconsoleHosts reads "ip host" lines. Empty lines and # comments are ignored.
func ParseNetconsoleHosts(r io.Reader) (*NetconsoleHosts, error) {
	h := &NetconsoleHosts{m: map[netip.Addr]string{}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("netconsole hosts line %d: want \"ip host\"", n)
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil || !wire.ValidHost(f[1]) {
			return nil, fmt.Errorf("netconsole hosts line %d: bad ip or host name", n)
		}
		h.m[ip.Unmap()] = f[1]
	}
	return h, sc.Err()
}

// LoadNetconsoleHosts reads a hosts file.
func LoadNetconsoleHosts(path string) (*NetconsoleHosts, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseNetconsoleHosts(f)
}

// Lookup returns the host name of ip, or "".
func (h *NetconsoleHosts) Lookup(ip netip.Addr) string {
	if h == nil {
		return ""
	}
	return h.m[ip.Unmap()]
}

// Netconsole receives kernel lines sent by the kernel itself, which still works after a panic stopped the agent.
// The lines are plain text, so only addresses in From and listed in Hosts are taken.
type Netconsole struct {
	In    *Ingestor
	From  []netip.Prefix
	Hosts atomic.Pointer[NetconsoleHosts]

	frags map[string]*ncFrag // by source address and record head
}

// fragWait is how long fragments of one record wait for the rest.
const fragWait = 5 * time.Second

// Listen reads netconsole datagrams from conn until it is closed.
func (nc *Netconsole) Listen(conn net.PacketConn) error {
	nc.frags = map[string]*ncFrag{}
	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			nc.In.Log.Warn("netconsole read", "err", err)
			continue
		}
		nc.Handle(buf[:n], addr, nc.In.now())
	}
}

// Handle checks one datagram and queues the record it completes, if any.
func (nc *Netconsole) Handle(b []byte, from net.Addr, now time.Time) {
	invalid := nc.In.Metrics.Invalid
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		invalid.WithLabelValues("netconsole_source").Inc()
		return
	}
	ip := ua.AddrPort().Addr().Unmap()
	host := nc.Hosts.Load().Lookup(ip)
	allowed := false
	for _, p := range nc.From {
		allowed = allowed || p.Contains(ip)
	}
	if !allowed || host == "" {
		invalid.WithLabelValues("netconsole_source").Inc()
		return
	}
	head, frag, body, err := parseNetconsole(b)
	if err != nil {
		invalid.WithLabelValues("netconsole_format").Inc()
		return
	}
	if frag[0] < 0 {
		nc.In.queueNetconsole(toLine(host, head, body))
		return
	}
	for k, f := range nc.frags {
		if now.Sub(f.first) > fragWait {
			delete(nc.frags, k)
		}
	}
	key := ip.String() + "|" + strings.Join(head, ",")
	f := nc.frags[key]
	if f == nil {
		if len(nc.frags) >= 1000 {
			invalid.WithLabelValues("netconsole_format").Inc()
			return
		}
		f = &ncFrag{body: make([]byte, frag[1]), first: now}
		nc.frags[key] = f
	}
	if len(f.body) != frag[1] || frag[0]+len(body) > len(f.body) {
		delete(nc.frags, key)
		invalid.WithLabelValues("netconsole_format").Inc()
		return
	}
	f.got += copy(f.body[frag[0]:], body)
	if f.got >= len(f.body) {
		delete(nc.frags, key)
		nc.In.queueNetconsole(toLine(host, head, f.body))
	}
}
