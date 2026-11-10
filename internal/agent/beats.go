package agent

import (
	"sync"

	"lastgasp/internal/wire"
)

// maxBeatSeqs bounds the heartbeats kept for a resend. Older ones stay missing on the server.
const maxBeatSeqs = 64

// beatSeq is a heartbeat sent with a seq and not confirmed by a server yet.
type beatSeq struct {
	seq, tx uint64
	resend  bool
}

// beatSeqs holds the seqs of unconfirmed heartbeats. A heartbeat lost on the way, for example
// while the server restarts, is sent again with its seq, so the server does not count it as missing.
type beatSeqs struct {
	mu   sync.Mutex
	sent []beatSeq // oldest first
}

// add keeps seq, sent at transmission tx.
func (b *beatSeqs) add(seq, tx uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == maxBeatSeqs {
		b.sent = append(b.sent[:0], b.sent[1:]...)
	}
	b.sent = append(b.sent, beatSeq{seq: seq, tx: tx})
}

// ack drops confirmed heartbeats, and marks missing ones sent before beatTx for a resend.
func (b *beatSeqs) ack(upto uint64, missing []wire.Range, beatTx uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	kept := b.sent[:0]
	m := 0
	for _, s := range b.sent {
		if s.seq > upto {
			kept = append(kept, s)
			continue
		}
		for m < len(missing) && missing[m].To < s.seq {
			m++
		}
		if m < len(missing) && missing[m].From <= s.seq {
			s.resend = s.resend || s.tx < beatTx
			kept = append(kept, s)
		}
	}
	b.sent = kept
}

// next returns the oldest heartbeat seq to send again.
func (b *beatSeqs) next() (uint64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.sent {
		if s.resend {
			return s.seq, true
		}
	}
	return 0, false
}

// resent notes that seq went out again at transmission tx.
func (b *beatSeqs) resent(seq, tx uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.sent {
		if b.sent[i].seq == seq {
			b.sent[i].tx, b.sent[i].resend = tx, false
		}
	}
}

// oldest returns the lowest unconfirmed heartbeat seq, or 0.
func (b *beatSeqs) oldest() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == 0 {
		return 0
	}
	return b.sent[0].seq
}
