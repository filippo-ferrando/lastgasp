package server

import (
	"sync"
	"time"

	"lastgasp/internal/wire"
)

// maxPending bounds the answered handshakes of one agent run that did not carry data yet.
const maxPending = 4

type liveSession struct {
	s       *wire.Session
	created time.Time
}

// runSessions holds the version 5 sessions of one agent run.
type runSessions struct {
	lastInit          uint64 // highest handshake number answered
	pending           []liveSession
	current, previous liveSession
}

// Sessions keeps the version 5 sessions of every agent run, in memory only, so a server restart forgets them.
type Sessions struct {
	mu   sync.Mutex
	runs map[ackKey]*runSessions
}

func NewSessions() *Sessions { return &Sessions{runs: map[ackKey]*runSessions{}} }

// Fresh reports whether a handshake init with this number was not answered yet, so a replayed init is refused.
func (t *Sessions) Fresh(k ackKey, number uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.runs[k]
	return r == nil || number > r.lastInit
}

// Add keeps an answered handshake as pending. It replaces no working session: a replayed init
// can only make a pending one, and only the agent can move it on with data.
func (t *Sessions) Add(k ackKey, number uint64, s *wire.Session, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.runs[k]
	if r == nil {
		if len(t.runs) >= cacheLimit {
			t.sweep(now)
		}
		if len(t.runs) >= cacheLimit {
			// Agents start a new handshake once their acks stop, so this only costs a short pause.
			clear(t.runs)
		}
		r = &runSessions{}
		t.runs[k] = r
	}
	r.lastInit = max(r.lastInit, number)
	if len(r.pending) >= maxPending {
		r.pending = r.pending[1:]
	}
	r.pending = append(r.pending, liveSession{s, now})
}

func alive(l liveSession, now time.Time) bool {
	return l.s != nil && now.Sub(l.created) < wire.RejectAfter
}

// Lookup returns the session id of agent run k, or nil when it is unknown or too old.
func (t *Sessions) Lookup(k ackKey, id uint32, now time.Time) *wire.Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.runs[k]
	if r == nil {
		return nil
	}
	for _, l := range append([]liveSession{r.current, r.previous}, r.pending...) {
		if l.s != nil && l.s.ID == id {
			if !alive(l, now) {
				return nil
			}
			return l.s
		}
	}
	return nil
}

// Confirm is called once s opened a data packet. A pending session then becomes the current one,
// with older pending ones dropped, as the agent only uses its newest session.
func (t *Sessions) Confirm(k ackKey, s *wire.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.runs[k]
	if r == nil || r.current.s == s {
		return
	}
	for i, l := range r.pending {
		if l.s == s {
			r.previous, r.current = r.current, l
			r.pending = append(r.pending[:0], r.pending[i+1:]...)
			return
		}
	}
}

// Sweep removes sessions that can no longer be used.
func (t *Sessions) Sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep(now)
}

func (t *Sessions) sweep(now time.Time) {
	for k, r := range t.runs {
		if !alive(r.current, now) {
			r.current = liveSession{}
		}
		if !alive(r.previous, now) {
			r.previous = liveSession{}
		}
		kept := r.pending[:0]
		for _, l := range r.pending {
			if alive(l, now) {
				kept = append(kept, l)
			}
		}
		r.pending = kept
		if r.current.s == nil && r.previous.s == nil && len(r.pending) == 0 {
			delete(t.runs, k)
		}
	}
}

// Len returns the number of agent runs with a session.
func (t *Sessions) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.runs)
}
