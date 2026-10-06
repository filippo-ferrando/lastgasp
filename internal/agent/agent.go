// Package agent collects kernel logs on the local machine and sends them to lastgasp servers.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"os"
	"strings"
	"time"

	"lastgasp/internal/wire"
)

// Config holds everything the agent needs. It is fully read before Run starts.
type Config struct {
	Servers       []string
	DNSServer     string
	Key           []byte
	Host          string
	BootIDPath    string
	KmsgPath      string
	PstoreDir     string
	BufferSize    int
	Rate          int
	Heartbeat     time.Duration
	WaitAck       bool
	ResolveEvery  time.Duration
	MaxPstoreFile int64
}

// Run starts all workers and blocks until ctx is done.
func Run(ctx context.Context, cfg Config, log *Logger) error {
	res, err := NewResolver(cfg.Servers, cfg.DNSServer)
	if err != nil {
		return err
	}
	stats := &Stats{}
	queue := NewQueue(cfg.BufferSize)
	maxMsg := wire.MaxMsg(len(cfg.Host))

	split := func(kind wire.Kind, e Entry, seq, fileID uint64) []Item {
		parts := wire.SplitMessage(e.Msg, maxMsg)
		if len(parts) > 255 {
			parts = parts[:255]
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
	var pstoreQueue *Queue
	if cfg.PstoreDir != "" {
		lines, err := ReadPstore(cfg.PstoreDir, cfg.MaxPstoreFile)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("pstore: %v", err)
		}
		var items []Item
		for _, l := range lines {
			items = append(items, split(wire.KindPstore, l.Entry, l.Line, l.FileID)...)
			stats.PstoreRecords.Add(1)
		}
		if len(items) > 0 {
			pstoreQueue = NewQueue(len(items))
			for _, it := range items {
				pstoreQueue.Push(it)
			}
			log.Printf("pstore: queued %d lines from the previous boot", len(lines))
		}
	}

	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := res.Refresh(c); err != nil {
		log.Printf("dns: initial lookup: %v (will keep trying)", err)
	}
	cancel()

	sender := &Sender{
		Host: cfg.Host, BootID: ReadBootID(cfg.BootIDPath, log), Instance: randomUint64(),
		Key: cfg.Key, Queue: queue, Pstore: pstoreQueue, Resolver: res, Stats: stats, Log: log,
		Rate: cfg.Rate, Heartbeat: cfg.Heartbeat, WaitAck: cfg.WaitAck,
	}
	kmsg := &KmsgReader{Path: cfg.KmsgPath, Stats: stats, Log: log,
		OnEntry: func(e Entry) {
			for _, it := range split(wire.KindKmsg, e, e.Seq, 0) {
				if queue.Push(it) {
					stats.BufferDrops.Add(1)
				}
			}
		}}

	log.Printf("agent: host=%s boot=%s instance=%x servers=%s",
		cfg.Host, wire.FormatBootID(sender.BootID), sender.Instance, strings.Join(cfg.Servers, ","))

	done := make(chan struct{}, 3)
	for name, fn := range map[string]func(context.Context){
		"sender":   sender.Run,
		"kmsg":     kmsg.Run,
		"resolver": func(ctx context.Context) { res.Run(ctx, cfg.ResolveEvery, log) },
	} {
		go func() {
			supervise(ctx, name, log, fn)
			done <- struct{}{}
		}()
	}
	<-ctx.Done()
	// The kmsg reader can stay blocked in read, so only wait briefly for the others.
	select {
	case <-done:
	case <-time.After(time.Second):
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
