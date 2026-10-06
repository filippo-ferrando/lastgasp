package server

import (
	"sort"
	"strconv"
	"sync"
	"time"

	"lastgasp/internal/wire"
)

// StreamKey identifies one agent run. A restarted agent starts a new stream from seq 1.
type StreamKey struct {
	Host     string
	BootID   string
	Instance uint64
}

// Range is an inclusive range of missing sequence numbers.
type Range struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// Stream holds packet counters for one agent run.
type Stream struct {
	Host       string     `json:"host"`
	BootID     string     `json:"boot_id"`
	Instance   string     `json:"instance"` // hex, as JSON numbers cannot hold 64 bits
	MaxSeq     uint64     `json:"max_seq"`
	Received   uint64     `json:"received"`
	Duplicates uint64     `json:"duplicates"`
	Gaps       uint64     `json:"gaps"`      // packets found missing, ever
	Recovered  uint64     `json:"recovered"` // missing packets that arrived late
	MissingSet []Range    `json:"missing_ranges"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	Agent      wire.Stats `json:"agent"` // counters from the newest heartbeat
}

// Missing is the number of packets still missing.
func (s *Stream) Missing() uint64 { return s.Gaps - s.Recovered }

func (s *Stream) key() StreamKey {
	inst, _ := strconv.ParseUint(s.Instance, 16, 64)
	return StreamKey{s.Host, s.BootID, inst}
}

// Tracker finds missing, late and duplicate packets per stream.
type Tracker struct {
	mu        sync.Mutex
	streams   map[StreamKey]*Stream
	dirty     map[StreamKey]bool
	maxRanges int
}

func NewTracker() *Tracker {
	return &Tracker{streams: map[StreamKey]*Stream{}, dirty: map[StreamKey]bool{}, maxRanges: 1000}
}

// Observe records a packet and returns false if it was already received.
func (t *Tracker) Observe(p *wire.Packet, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := StreamKey{p.Host, wire.FormatBootID(p.BootID), p.Instance}
	s := t.streams[k]
	if s == nil {
		s = &Stream{Host: k.Host, BootID: k.BootID, Instance: strconv.FormatUint(k.Instance, 16), FirstSeen: now}
		t.streams[k] = s
	}
	t.dirty[k] = true
	s.LastSeen = now

	switch {
	case p.Seq > s.MaxSeq:
		if p.Seq > s.MaxSeq+1 {
			s.MissingSet = append(s.MissingSet, Range{s.MaxSeq + 1, p.Seq - 1})
			s.Gaps += p.Seq - 1 - s.MaxSeq
			// Very old ranges are forgotten: they stay counted as missing, but a late arrival counts as duplicate.
			if len(s.MissingSet) > t.maxRanges {
				s.MissingSet = append([]Range(nil), s.MissingSet[len(s.MissingSet)-t.maxRanges:]...)
			}
		}
		s.MaxSeq = p.Seq
		if p.Kind == wire.KindHeartbeat {
			s.Agent = p.Stats
		}
	case s.takeMissing(p.Seq):
		s.Recovered++
	default:
		s.Duplicates++
		return false
	}
	s.Received++
	return true
}

// takeMissing removes seq from the missing ranges and reports whether it was there.
func (s *Stream) takeMissing(seq uint64) bool {
	i := sort.Search(len(s.MissingSet), func(i int) bool { return s.MissingSet[i].To >= seq })
	if i == len(s.MissingSet) || s.MissingSet[i].From > seq {
		return false
	}
	r := s.MissingSet[i]
	switch {
	case r.From == seq && r.To == seq:
		s.MissingSet = append(s.MissingSet[:i], s.MissingSet[i+1:]...)
	case r.From == seq:
		s.MissingSet[i].From++
	case r.To == seq:
		s.MissingSet[i].To--
	default:
		s.MissingSet = append(s.MissingSet[:i+1], s.MissingSet[i:]...)
		s.MissingSet[i] = Range{r.From, seq - 1}
		s.MissingSet[i+1] = Range{seq + 1, r.To}
	}
	return true
}

// Snapshot returns a copy of every stream.
func (t *Tracker) Snapshot() []Stream {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Stream, 0, len(t.streams))
	for _, s := range t.streams {
		c := *s
		c.MissingSet = append([]Range(nil), s.MissingSet...)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}

// TakeDirty returns copies of streams changed since the last call.
func (t *Tracker) TakeDirty() []Stream {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Stream, 0, len(t.dirty))
	for k := range t.dirty {
		c := *t.streams[k]
		c.MissingSet = append([]Range(nil), c.MissingSet...)
		out = append(out, c)
	}
	clear(t.dirty)
	return out
}

// MarkDirty puts streams back after a failed save.
func (t *Tracker) MarkDirty(streams []Stream) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range streams {
		t.dirty[streams[i].key()] = true
	}
}

// Load restores saved streams, so a server restart does not count old packets as new gaps.
func (t *Tracker) Load(streams []Stream) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range streams {
		s := streams[i]
		t.streams[s.key()] = &s
	}
}

// Restore puts back streams that are not tracked, and leaves live ones alone.
func (t *Tracker) Restore(streams []Stream) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range streams {
		s := streams[i]
		if k := s.key(); t.streams[k] == nil {
			t.streams[k] = &s
		}
	}
}

// HostSummary adds up all streams of one host.
type HostSummary struct {
	Host       string     `json:"host"`
	BootID     string     `json:"boot_id"`
	LastSeen   time.Time  `json:"last_seen"`
	Up         bool       `json:"up"`
	Received   uint64     `json:"received"`
	Missing    uint64     `json:"missing"`
	Gaps       uint64     `json:"gaps"`
	Recovered  uint64     `json:"recovered"`
	Duplicates uint64     `json:"duplicates"`
	Streams    int        `json:"streams"`
	Agent      wire.Stats `json:"agent"` // summed over all agent runs, Buffered from the newest
}

// Hosts summarizes streams per host. A host is up when it sent something within staleAfter.
func (t *Tracker) Hosts(now time.Time, staleAfter time.Duration) []HostSummary {
	var out []HostSummary
	for _, s := range t.Snapshot() {
		if len(out) == 0 || out[len(out)-1].Host != s.Host {
			out = append(out, HostSummary{Host: s.Host})
		}
		h := &out[len(out)-1]
		h.Streams++
		h.Received += s.Received
		h.Missing += s.Missing()
		h.Gaps += s.Gaps
		h.Recovered += s.Recovered
		h.Duplicates += s.Duplicates
		a := &h.Agent
		a.KmsgRead += s.Agent.KmsgRead
		a.KmsgOverruns += s.Agent.KmsgOverruns
		a.KmsgInvalid += s.Agent.KmsgInvalid
		a.BufferDrops += s.Agent.BufferDrops
		a.SendErrors += s.Agent.SendErrors
		a.PstoreRecords += s.Agent.PstoreRecords
		if !s.LastSeen.Before(h.LastSeen) {
			h.LastSeen, h.BootID = s.LastSeen, s.BootID
			a.Buffered, a.UptimeSec = s.Agent.Buffered, s.Agent.UptimeSec
		}
	}
	for i := range out {
		out[i].Up = now.Sub(out[i].LastSeen) <= staleAfter
	}
	return out
}

// Prune removes streams not seen since cutoff and returns them.
func (t *Tracker) Prune(cutoff time.Time) []Stream {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Stream
	for k, s := range t.streams {
		if s.LastSeen.Before(cutoff) {
			out = append(out, *s)
			delete(t.streams, k)
			delete(t.dirty, k)
		}
	}
	return out
}
