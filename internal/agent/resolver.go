package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type target struct {
	host string
	port int
	addr *net.UDPAddr // last known good address
}

// Resolver keeps the last good address of each server. A failed lookup never removes a known address.
type Resolver struct {
	mu      sync.RWMutex
	targets []*target
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
}

// NewResolver parses "host:port" targets. dnsServer, when set, is used instead of /etc/resolv.conf.
func NewResolver(targets []string, dnsServer string) (*Resolver, error) {
	r := &Resolver{}
	res := &net.Resolver{PreferGo: true}
	if dnsServer != "" {
		d := net.Dialer{Timeout: 2 * time.Second}
		res.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, dnsServer)
		}
	}
	r.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return res.LookupNetIP(ctx, "ip", host)
	}
	for _, t := range targets {
		host, portStr, err := net.SplitHostPort(t)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", t, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("server %q: bad port", t)
		}
		tg := &target{host: host, port: port}
		if ip, err := netip.ParseAddr(host); err == nil {
			tg.addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
		}
		r.targets = append(r.targets, tg)
	}
	if len(r.targets) == 0 {
		return nil, fmt.Errorf("no server configured")
	}
	return r, nil
}

// Refresh looks up every named target and returns the first error seen.
func (r *Resolver) Refresh(ctx context.Context) error {
	var firstErr error
	for _, t := range r.targets {
		if _, err := netip.ParseAddr(t.host); err == nil {
			continue
		}
		ips, err := r.lookup(ctx, t.host)
		if err == nil && len(ips) == 0 {
			err = fmt.Errorf("no address for %s", t.host)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ips[0].Unmap(), uint16(t.port)))
		r.mu.Lock()
		t.addr = addr
		r.mu.Unlock()
	}
	return firstErr
}

// Addrs returns the known address of every target that has one.
func (r *Resolver) Addrs() []*net.UDPAddr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*net.UDPAddr, 0, len(r.targets))
	for _, t := range r.targets {
		if t.addr != nil {
			out = append(out, t.addr)
		}
	}
	return out
}

// Run refreshes addresses every interval, and faster while some target has no address yet.
func (r *Resolver) Run(ctx context.Context, every time.Duration, log *Logger) {
	for {
		wait := every
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := r.Refresh(c)
		cancel()
		if err != nil {
			log.Printf("dns: %v (keeping last known addresses)", err)
			if len(r.Addrs()) < len(r.targets) {
				wait = min(every, 5*time.Second)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
