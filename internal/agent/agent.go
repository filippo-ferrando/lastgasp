// Package agent collects kernel logs on the local machine and sends them to lastgasp servers.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"lastgasp/internal/version"
	"lastgasp/internal/wire"
)

// Config holds everything the agent needs. It is fully read before Run starts.
type Config struct {
	Servers    []string
	DNSServer  string
	Key        []byte
	Host       string
	BootIDPath string
	KmsgPath   string
	PstoreDir  string
	BufferSize int
	Rate       int
	Heartbeat  time.Duration
	WaitAck    bool
	// ForwardSecrecy uses version 5 packets with a handshake per server. It needs WaitAck.
	ForwardSecrecy bool
	ResolveEvery   time.Duration
	MaxPstoreFile  int64
	// StashPath is a file on tmpfs that keeps unconfirmed records across agent restarts, empty to disable.
	StashPath string
	StashSize int
}

// MaxBuffer bounds -buffer, as all slots are allocated and locked in memory at start.
const MaxBuffer = 1 << 20

// Validate checks the values that would make the agent misbehave later instead of failing at start.
func (c *Config) Validate() error {
	switch {
	case len(c.Servers) == 0:
		return errors.New("at least one server is required")
	case !wire.ValidHost(c.Host):
		return fmt.Errorf("hostname %q is not valid: at most %d bytes of UTF-8, no spaces or control characters", c.Host, wire.MaxHostLen)
	case len(c.Key) < 16:
		return errors.New("key must be at least 16 bytes")
	case c.BufferSize < 1 || c.BufferSize > MaxBuffer:
		return fmt.Errorf("buffer must be between 1 and %d", MaxBuffer)
	case c.Rate < 0:
		return errors.New("rate must not be negative")
	case c.Heartbeat != 0 && c.Heartbeat < 100*time.Millisecond:
		return errors.New("heartbeat must be 0 or at least 100ms")
	case c.WaitAck && c.Heartbeat == 0:
		return errors.New("wait-ack needs heartbeats, set -heartbeat or -wait-ack=false")
	case c.ResolveEvery < time.Second:
		return errors.New("resolve-every must be at least 1s")
	case c.StashPath != "" && (c.StashSize < MinStash || c.StashSize > MaxStash):
		return fmt.Errorf("stash-size must be between %d and %d bytes", MinStash, MaxStash)
	}
	for _, s := range c.Servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return fmt.Errorf("server %q: %w", s, err)
		}
	}
	if c.DNSServer != "" {
		if _, _, err := net.SplitHostPort(c.DNSServer); err != nil {
			return fmt.Errorf("dns %q: want ip:port: %w", c.DNSServer, err)
		}
	}
	return nil
}

// Run starts all workers and blocks until ctx is done.
func Run(ctx context.Context, cfg Config, log *Logger) error {
	res, err := NewResolver(cfg.Servers, cfg.DNSServer)
	if err != nil {
		return err
	}
	stats := &Stats{}
	queue := NewQueue(cfg.BufferSize)
	bootID := ReadBootID(cfg.BootIDPath, log)
	maxMsg := wire.MaxMsg(len(cfg.Host))

	split := func(kind wire.Kind, e Entry, seq, fileID uint64) []Item {
		parts := wire.SplitMessage(e.Msg, maxMsg)
		if len(parts) > 255 {
			// The part counter is one byte. The cut is counted like a drop, so it shows up on the server.
			parts = parts[:255]
			stats.BufferDrops.Add(1)
			log.Printf("message of %d bytes cut to 255 parts", len(e.Msg))
		}
		items := make([]Item, len(parts))
		for i, p := range parts {
			items[i] = Item{Kind: kind, Rec: wire.Record{Priority: e.Priority, Seq: seq, TsUsec: e.TsUsec, FileID: fileID,
				Part: uint8(i + 1), Parts: uint8(len(parts)), Msg: p}}
		}
		return items
	}

	// pstore holds the crash of the previous boot. It gets its own queue, sized to hold every line
	// and sent first, so the kernel buffer replay can never push it out.
	var items []Item
	if cfg.PstoreDir != "" {
		lines, err := ReadPstore(cfg.PstoreDir, cfg.MaxPstoreFile)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("pstore: %v", err)
		}
		for _, l := range lines {
			items = append(items, split(wire.KindPstore, l.Entry, l.Line, l.FileID)...)
			stats.PstoreRecords.Add(1)
		}
		if len(lines) > 0 {
			log.Printf("pstore: queued %d lines from the previous boot", len(lines))
		}
	}
	// Records the previous run of this boot did not get confirmed go in the same first queue.
	var stash *Stash
	if cfg.StashPath != "" {
		var recovered []Item
		var err error
		if stash, recovered, err = OpenStash(cfg.StashPath, cfg.StashSize, bootID, log); err != nil {
			log.Printf("stash: %v, records are not kept across restarts", err)
		} else if len(recovered) > 0 {
			log.Printf("stash: %d records from the previous run will be sent again", len(recovered))
			items = append(items, recovered...)
		}
	}
	var first *Queue
	if len(items) > 0 {
		first = NewQueue(len(items))
		if stash != nil {
			first.Mirror(stash, tagFirst)
		}
		for _, it := range items {
			first.Push(it)
		}
	}
	// The stash is never unmapped: the kmsg reader may still push records while the process exits.
	if stash != nil {
		queue.Mirror(stash, tagMain)
	}

	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := res.Refresh(c); err != nil {
		log.Printf("dns: initial lookup: %v (will keep trying)", err)
	}
	cancel()

	sender := &Sender{
		Host: cfg.Host, BootID: bootID, Instance: randomUint64(),
		Key: cfg.Key, Queue: queue, First: first, Resolver: res, Stats: stats, Log: log,
		Rate: cfg.Rate, Heartbeat: cfg.Heartbeat, WaitAck: cfg.WaitAck, ForwardSecrecy: cfg.ForwardSecrecy, Version: version.String(),
	}
	if cfg.ForwardSecrecy && !sender.fs() {
		log.Printf("agent: forward secrecy needs -wait-ack and -heartbeat, sending version 4 packets without it")
	}
	kmsg := &KmsgReader{Path: cfg.KmsgPath, Stats: stats, Log: log,
		OnEntry: func(e Entry) {
			for _, it := range split(wire.KindKmsg, e, e.Seq, 0) {
				if queue.Push(it) {
					stats.BufferDrops.Add(1)
				}
			}
		}}

	log.Printf("agent: version=%s host=%s boot=%s instance=%x servers=%s", version.String(),
		cfg.Host, wire.FormatBootID(sender.BootID), sender.Instance, strings.Join(cfg.Servers, ","))

	workers := map[string]func(context.Context){
		"sender":   sender.Run,
		"kmsg":     kmsg.Run,
		"resolver": func(ctx context.Context) { res.Run(ctx, cfg.ResolveEvery, log) },
	}
	done := make(chan string, len(workers))
	for name, fn := range workers {
		go func() {
			supervise(ctx, name, log, fn)
			done <- name
		}()
	}
	<-ctx.Done()
	// The sender drains its queue first. The kmsg reader can stay blocked in read, so it is not waited for.
	limit := time.After(drainTime + time.Second)
	for range len(workers) {
		select {
		case name := <-done:
			if name == "sender" {
				return nil
			}
		case <-limit:
			return nil
		}
	}
	return nil
}

// ReadBootID reads the kernel boot ID. A random ID is used if it cannot be read, so logs are never lost.
func ReadBootID(path string, log *Logger) [16]byte {
	b, err := os.ReadFile(path)
	if err == nil {
		if id, err := wire.ParseBootID(string(b)); err == nil {
			return id
		}
	}
	log.Printf("boot id: cannot read %s, using a random id", path)
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		binary.BigEndian.PutUint64(id[:], uint64(time.Now().UnixNano()))
	}
	return id
}

func randomUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}
