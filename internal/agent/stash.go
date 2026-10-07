package agent

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"sync"

	"lastgasp/internal/wire"
)

// Stash keeps a copy of queued records in shared memory backed by a tmpfs file, so a new agent run
// after a crash or an upgrade can send what the old run had not got confirmed. It never touches a disk.
type Stash struct {
	mu    sync.Mutex
	hdr   []byte // stashHeader bytes at the start of the mapping
	ring  []byte
	close func() error
}

// Stash header layout. head and tail are byte offsets that only grow, the ring index is offset % len(ring).
const (
	stashMagic   = "LGS1"
	stashVersion = 1
	stashHeader  = 4096
	offVersion   = 4
	offBoot      = 8
	offRingSize  = 24
	offHead      = 32
	offTail      = 40
	offNeed      = 48 // one uint64 per queue tag
	stashTags    = 2
	// Entry: length, crc32 of the rest, tag, item id, kind, priority, seq, ts, file id, part, parts, then the message.
	entryFixed = 4 + 4 + 1 + 8 + 1 + 2 + 8 + 8 + 8 + 1 + 1
)

// Queue tags in the stash.
const (
	tagFirst uint8 = 0 // pstore lines and records recovered from a previous run
	tagMain  uint8 = 1 // kmsg records
)

// MinStash and MaxStash bound the ring size in bytes.
const (
	MinStash = 64 << 10
	MaxStash = 1 << 30
)

var errStashFormat = errors.New("stash: no valid content")

// newStash uses mem, at least stashHeader+MinStash bytes, as the stash. Old content stays until reset.
func newStash(mem []byte, close func() error) *Stash {
	return &Stash{hdr: mem[:stashHeader], ring: mem[stashHeader:], close: close}
}

func (s *Stash) u64(off int) uint64           { return binary.LittleEndian.Uint64(s.hdr[off:]) }
func (s *Stash) put(off int, v uint64)        { binary.LittleEndian.PutUint64(s.hdr[off:], v) }
func (s *Stash) at(off uint64) int            { return int(off % uint64(len(s.ring))) }
func (s *Stash) need(tag uint8) uint64        { return s.u64(offNeed + 8*int(tag)) }
func (s *Stash) setNeed(tag uint8, id uint64) { s.put(offNeed+8*int(tag), id) }

// read copies len(b) ring bytes starting at offset off, across the end of the ring.
func (s *Stash) read(off uint64, b []byte) {
	n := copy(b, s.ring[s.at(off):])
	copy(b[n:], s.ring)
}

func (s *Stash) write(off uint64, b []byte) {
	n := copy(s.ring[s.at(off):], b)
	copy(s.ring, b[n:])
}

// reset empties the stash and marks it as belonging to boot.
func (s *Stash) reset(boot [16]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.hdr)
	copy(s.hdr, stashMagic)
	binary.LittleEndian.PutUint32(s.hdr[offVersion:], stashVersion)
	copy(s.hdr[offBoot:], boot[:])
	s.put(offRingSize, uint64(len(s.ring)))
}

// Append saves a copy of an item pushed to the queue with the given tag. When the ring is full,
// the oldest entries are overwritten.
func (s *Stash) Append(tag uint8, id uint64, it *Item) {
	n := entryFixed + len(it.Rec.Msg)
	if n > len(s.ring) {
		return
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b, uint32(n))
	b[8] = tag
	binary.LittleEndian.PutUint64(b[9:], id)
	b[17] = byte(it.Kind)
	r := &it.Rec
	binary.LittleEndian.PutUint16(b[18:], r.Priority)
	binary.LittleEndian.PutUint64(b[20:], r.Seq)
	binary.LittleEndian.PutUint64(b[28:], r.TsUsec)
	binary.LittleEndian.PutUint64(b[36:], r.FileID)
	b[44], b[45] = r.Part, r.Parts
	copy(b[entryFixed:], r.Msg)
	binary.LittleEndian.PutUint32(b[4:], crc32.ChecksumIEEE(b[8:]))

	s.mu.Lock()
	defer s.mu.Unlock()
	head, tail := s.u64(offHead), s.u64(offTail)
	var l [4]byte
	for tail+uint64(n)-head > uint64(len(s.ring)) {
		s.read(head, l[:])
		size := uint64(binary.LittleEndian.Uint32(l[:]))
		if size < entryFixed || head+size > tail {
			head = tail
			break
		}
		head += size
	}
	// The head moves before old bytes are overwritten, so a crash in between leaves a readable ring.
	s.put(offHead, head)
	s.write(tail, b)
	s.put(offTail, tail+uint64(n))
}

// Need records that the queue with tag no longer needs items with an id below id.
func (s *Stash) Need(tag uint8, id uint64) {
	s.mu.Lock()
	s.setNeed(tag, id)
	s.mu.Unlock()
}

// recover returns the items a previous run of the same boot still needed, oldest first.
func (s *Stash) recover(boot [16]byte) ([]Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if string(s.hdr[:4]) != stashMagic || binary.LittleEndian.Uint32(s.hdr[offVersion:]) != stashVersion ||
		s.u64(offRingSize) != uint64(len(s.ring)) {
		return nil, errStashFormat
	}
	if [16]byte(s.hdr[offBoot:offBoot+16]) != boot {
		return nil, errors.New("stash: records of another boot")
	}
	head, tail := s.u64(offHead), s.u64(offTail)
	if tail < head || tail-head > uint64(len(s.ring)) {
		return nil, errStashFormat
	}
	var out []Item
	var l [4]byte
	for head < tail {
		s.read(head, l[:])
		n := uint64(binary.LittleEndian.Uint32(l[:]))
		if n < entryFixed || head+n > tail {
			break
		}
		b := make([]byte, n)
		s.read(head, b)
		// A bad checksum is an entry cut by a crash while it was written, so nothing after it is valid.
		if binary.LittleEndian.Uint32(b[4:]) != crc32.ChecksumIEEE(b[8:]) {
			break
		}
		head += n
		tag, id := b[8], binary.LittleEndian.Uint64(b[9:])
		if tag >= stashTags || id < s.need(tag) {
			continue
		}
		out = append(out, Item{Kind: wire.Kind(b[17]), Rec: wire.Record{
			Priority: binary.LittleEndian.Uint16(b[18:]), Seq: binary.LittleEndian.Uint64(b[20:]),
			TsUsec: binary.LittleEndian.Uint64(b[28:]), FileID: binary.LittleEndian.Uint64(b[36:]),
			Part: b[44], Parts: b[45], Msg: string(b[entryFixed:]),
		}})
	}
	return out, nil
}

// Close unmaps the stash. The file stays, so the next run can read it.
func (s *Stash) Close() error {
	if s == nil || s.close == nil {
		return nil
	}
	return s.close()
}
