package agent

import (
	"sort"
	"sync"

	"lastgasp/internal/wire"
)

// Item is a record waiting to be sent, or sent and waiting for a server to confirm it.
type Item struct {
	id     uint64
	seq    uint64 // packet seq once sent, 0 before
	tx     uint64 // sender transmission count at the last send
	done   bool   // confirmed by a server
	resend bool   // in the resend list
	Kind   wire.Kind
	Rec    wire.Record
}

// Queue is a fixed size ring buffer. When full, the oldest item is dropped so memory never grows.
// Sent items stay until a server confirms them, so lost packets can be sent again.
type Queue struct {
	mu     sync.Mutex
	buf    []Item
	head   int
	n      int      // used slots, from head
	sent   int      // the first sent slots, from head
	done   int      // confirmed items among the sent slots
	resend []uint64 // seqs to send again, oldest first
	nextID uint64
	notify chan struct{}
	stash  *Stash // keeps a copy of pushed items, may be nil
	tag    uint8
}

func NewQueue(capacity int) *Queue {
	if capacity < 1 {
		capacity = 1
	}
	return &Queue{buf: make([]Item, capacity), notify: make(chan struct{}, 1)}
}

func (q *Queue) at(i int) *Item { return &q.buf[(q.head+i)%len(q.buf)] }

// Mirror copies every item pushed from now on to s, under tag.
func (q *Queue) Mirror(s *Stash, tag uint8) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stash, q.tag = s, tag
	q.syncStash()
}

// syncStash tells the stash the id of the oldest item still needed.
func (q *Queue) syncStash() {
	if q.stash == nil {
		return
	}
	need := q.nextID + 1
	if q.n > 0 {
		need = q.at(0).id
	}
	q.stash.Need(q.tag, need)
}

// Push adds an item and reports whether an item never sent was dropped to make room.
// A sent but unconfirmed item dropped this way most likely arrived, so it is not reported.
func (q *Queue) Push(it Item) (dropped bool) {
	q.mu.Lock()
	q.nextID++
	it.id, it.seq, it.tx, it.done, it.resend = q.nextID, 0, 0, false, false
	if q.n == len(q.buf) {
		if q.sent > 0 {
			q.sent--
		} else {
			dropped = true
		}
		*q.at(0) = Item{}
		q.head = (q.head + 1) % len(q.buf)
		q.n--
		q.trim()
	}
	q.buf[(q.head+q.n)%len(q.buf)] = it
	q.n++
	if q.stash != nil {
		q.stash.Append(q.tag, it.id, &it)
	}
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return dropped
}

// trim moves the head past confirmed items, so the head is always an item still needed.
func (q *Queue) trim() {
	for q.sent > 0 && q.at(0).done {
		*q.at(0) = Item{}
		q.head = (q.head + 1) % len(q.buf)
		q.n--
		q.sent--
		q.done--
	}
	q.syncStash()
}

// find returns the index of the sent item with seq, or -1. Sent items are in seq order.
func (q *Queue) find(seq uint64) int {
	i := sort.Search(q.sent, func(i int) bool { return q.at(i).seq >= seq })
	if i < q.sent && q.at(i).seq == seq {
		return i
	}
	return -1
}

// Next returns the next item to send: an item to send again first, then the oldest item never sent.
func (q *Queue) Next() (Item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.resend) > 0 {
		if i := q.find(q.resend[0]); i >= 0 && q.at(i).resend && !q.at(i).done {
			return *q.at(i), true
		}
		// Sent, confirmed or dropped since it was listed.
		q.resend = q.resend[1:]
	}
	if q.sent == q.n {
		return Item{}, false
	}
	return *q.at(q.sent), true
}

// Sent records that it, returned by Next, went out as packet seq at transmission tx.
// With keep false the item is done at once, for agents that do not wait for acks.
func (q *Queue) Sent(it Item, seq, tx uint64, keep bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if it.seq != 0 {
		// Its entry in the resend list is skipped by Next from now on.
		if i := q.find(it.seq); i >= 0 && q.at(i).id == it.id {
			q.at(i).tx, q.at(i).resend = tx, false
		}
		return
	}
	// The item may have been dropped by a Push since Next returned it.
	if q.sent == q.n || q.at(q.sent).id != it.id {
		return
	}
	cur := q.at(q.sent)
	cur.seq, cur.tx = seq, tx
	q.sent++
	if !keep {
		cur.done = true
		q.done++
		q.trim()
	}
}

// Drop removes it, returned by Next, when it can never be sent.
func (q *Queue) Drop(it Item) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if it.seq != 0 || q.sent == q.n || q.at(q.sent).id != it.id {
		return
	}
	cur := q.at(q.sent)
	// It takes the seq of the item before it, so sent items stay in seq order.
	if q.sent > 0 {
		cur.seq = q.at(q.sent - 1).seq
	}
	cur.done = true
	q.sent++
	q.done++
	q.trim()
}

// Ack applies what a server received: every packet up to upto except the missing ranges.
// Missing items last sent before transmission beatTx (the heartbeat the ack answers) are sent again.
func (q *Queue) Ack(upto uint64, missing []wire.Range, beatTx uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	m := 0
	for i := 0; i < q.sent; i++ {
		it := q.at(i)
		if it.seq > upto {
			break
		}
		if it.done {
			continue
		}
		for m < len(missing) && missing[m].To < it.seq {
			m++
		}
		if m < len(missing) && missing[m].From <= it.seq {
			if it.tx < beatTx && !it.resend {
				it.resend = true
				q.resend = append(q.resend, it.seq)
			}
			continue
		}
		it.done = true
		q.done++
	}
	sort.Slice(q.resend, func(i, j int) bool { return q.resend[i] < q.resend[j] })
	q.trim()
}

// Oldest returns the seq of the oldest sent item not confirmed yet, or 0.
func (q *Queue) Oldest() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.sent == 0 {
		return 0
	}
	return q.at(0).seq
}

// Pending returns copies of the items no server confirmed yet, sent or not, oldest first.
func (q *Queue) Pending() []Item {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []Item
	for i := 0; i < q.n; i++ {
		if it := q.at(i); !it.done {
			out = append(out, *it)
		}
	}
	return out
}

// Unconfirmed returns the number of items sent and not confirmed yet.
func (q *Queue) Unconfirmed() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sent - q.done
}

// Len returns the number of items held, sent or not.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n - q.done
}

// Cap returns the number of slots.
func (q *Queue) Cap() int { return len(q.buf) }

// Ready fires after a Push.
func (q *Queue) Ready() <-chan struct{} { return q.notify }
