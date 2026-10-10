package server

import (
	"sync"
	"time"

	"lastgasp/internal/wire"
)

// maxPending bounds the answered handshakes of one agent run that did not carry data yet.
const maxPending = 4

// maxRunsPerHost bounds the agent runs with sessions per host. A host has one agent run at a time,
// a few more for 3 minutes after agent restarts or a reboot.
const maxRunsPerHost = 16

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
	mu    sync.Mutex
	hosts map[string]map[ackKey]*runSessions
	n     int // agent runs in hosts
}

func NewSessions() *Sessions { return &Sessions{hosts: map[string]map[ackKey]*runSessions{}} }

func (t *Sessions) run(k ackKey) *runSessions { return t.hosts[k.host][k] }

func (t *Sessions) drop(k ackKey) {
	runs := t.hosts[k.host]
	delete(runs, k)
	t.n--
	if len(runs) == 0 {
		delete(t.hosts, k.host)
	}
}

// evictOne drops a run without a confirmed session if there is one, else the run with the oldest session.
func (t *Sessions) evictOne(runs map[ackKey]*runSessions) {
	var oldest *ackKey
	for k, r := range runs {
		if r.current.s == nil {
			t.drop(k)
			return
		}
		if oldest == nil || r.current.created.Before(runs[*oldest].current.created) {
			oldest = &k
		}
	}
	if oldest != nil {
		t.drop(*oldest)
	}
}

// Fresh reports whether a handshake init with this number was not answered yet, so a replayed init is refused.
func (t *Sessions) Fresh(k ackKey, number uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.run(k)
	return r == nil || number > r.lastInit
}

// Add keeps an answered handshake as pending. It replaces no working session: a replayed init
// can only make a pending one, and only the agent can move it on with data.
func (t *Sessions) Add(k ackKey, number uint64, s *wire.Session, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.run(k)
	if r == nil {
		if t.n >= cacheLimit {
			t.sweep(now)
		}
		if t.n >= cacheLimit {
			// Working sessions are kept, an agent that lost its run starts a new handshake once its acks stop.
			for _, runs := range t.hosts {
				for other, o := range runs {
					if o.current.s == nil {
						t.drop(other)
					}
				}
			}
		}
		if t.n >= cacheLimit {
			for _, runs := range t.hosts {
				t.evictOne(runs)
				break
			}
		}
		if runs := t.hosts[k.host]; len(runs) >= maxRunsPerHost {
			t.evictOne(runs)
		}
		if t.hosts[k.host] == nil {
			t.hosts[k.host] = map[ackKey]*runSessions{}
		}
		r = &runSessions{}
		t.hosts[k.host][k] = r
		t.n++
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
	r := t.run(k)
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
	r := t.run(k)
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
	for _, runs := range t.hosts {
		for k, r := range runs {
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
				t.drop(k)
			}
		}
	}
}

// Len returns the number of agent runs with a session.
func (t *Sessions) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}
