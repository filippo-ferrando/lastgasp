package agent

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"
	"sync/atomic"
	"time"

	"lastgasp/internal/wire"
)

// Stats are agent counters, safe for concurrent use.
type Stats struct {
	KmsgRead      atomic.Uint64
	KmsgOverruns  atomic.Uint64
	KmsgInvalid   atomic.Uint64
	BufferDrops   atomic.Uint64
	SendErrors    atomic.Uint64
	PstoreRecords atomic.Uint64
}

func (s *Stats) snapshot(buffered int, uptime time.Duration) wire.Stats {
	return wire.Stats{
		KmsgRead:      s.KmsgRead.Load(),
		KmsgOverruns:  s.KmsgOverruns.Load(),
		KmsgInvalid:   s.KmsgInvalid.Load(),
		BufferDrops:   s.BufferDrops.Load(),
		SendErrors:    s.SendErrors.Load(),
		PstoreRecords: s.PstoreRecords.Load(),
		UptimeSec:     uint64(uptime / time.Second),
		Buffered:      uint32(buffered),
	}
}

// Logger never blocks the caller. If the output is stuck (for example journald hangs), lines are dropped.
type Logger struct {
	ch      chan string
	Dropped atomic.Uint64
}

func NewLogger(w io.Writer, size int) *Logger {
	l := &Logger{ch: make(chan string, size)}
	go func() {
		for line := range l.ch {
			io.WriteString(w, line)
		}
	}()
	return l
}

func (l *Logger) Printf(format string, args ...any) {
	if l == nil {
		return
	}
	// UTC avoids reading /etc/localtime from disk.
	line := time.Now().UTC().Format("2006-01-02T15:04:05.000Z ") + fmt.Sprintf(format, args...) + "\n"
	select {
	case l.ch <- line:
	default:
		l.Dropped.Add(1)
	}
}

type backoff struct {
	min, max, cur time.Duration
}

func newBackoff(min, max time.Duration) *backoff { return &backoff{min: min, max: max, cur: min} }

func (b *backoff) Reset() { b.cur = b.min }

func (b *backoff) Sleep(ctx context.Context) {
	t := time.NewTimer(b.cur)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	b.cur = min(b.cur*2, b.max)
}

// supervise runs fn again after a panic or an early return, until ctx is done.
func supervise(ctx context.Context, name string, log *Logger, fn func(context.Context)) {
	for ctx.Err() == nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("%s: panic: %v\n%s", name, r, debug.Stack())
				}
			}()
			fn(ctx)
		}()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}
