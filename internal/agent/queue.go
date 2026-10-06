package agent

import (
	"sync"

	"lastgasp/internal/wire"
)

// Item is a record waiting to be sent.
type Item struct {
	id   uint64
	Kind wire.Kind
	Rec  wire.Record
}

// Queue is a fixed size ring buffer. When full, the oldest item is dropped so memory never grows.
type Queue struct {
	mu     sync.Mutex
	buf    []Item
	head   int
	n      int
	nextID uint64
	notify chan struct{}
}

func NewQueue(capacity int) *Queue {
	if capacity < 1 {
		capacity = 1
	}
	return &Queue{buf: make([]Item, capacity), notify: make(chan struct{}, 1)}
}

// Push adds an item and reports whether an older item was dropped to make room.
func (q *Queue) Push(it Item) (dropped bool) {
	q.mu.Lock()
	q.nextID++
	it.id = q.nextID
	if q.n == len(q.buf) {
		q.head = (q.head + 1) % len(q.buf)
		q.n--
		dropped = true
	}
	q.buf[(q.head+q.n)%len(q.buf)] = it
	q.n++
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return dropped
}

// Peek returns the oldest item without removing it.
func (q *Queue) Peek() (Item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		return Item{}, false
	}
	return q.buf[q.head], true
}

// Done removes the item returned by Peek. It does nothing if that item was already dropped.
func (q *Queue) Done(it Item) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n > 0 && q.buf[q.head].id == it.id {
		q.buf[q.head] = Item{}
		q.head = (q.head + 1) % len(q.buf)
		q.n--
	}
}

func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// Ready fires after a Push.
func (q *Queue) Ready() <-chan struct{} { return q.notify }
