package agent

import (
	"fmt"
	"testing"

	"lastgasp/internal/wire"
)

func memStash(ring int) *Stash {
	s := newStash(make([]byte, stashHeader+ring), nil)
	s.reset([16]byte{1})
	return s
}

func kmsgItem(seq uint64, msg string) Item {
	return Item{Kind: wire.KindKmsg, Rec: wire.Record{Priority: 3, Seq: seq, TsUsec: seq * 10, Part: 1, Parts: 1, Msg: msg}}
}

func msgs(items []Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.Rec.Msg)
	}
	return out
}

func TestStashKeepsUnconfirmedRecords(t *testing.T) {
	s := memStash(MinStash)
	q := NewQueue(10)
	q.Mirror(s, tagMain)
	for i := uint64(1); i <= 5; i++ {
		q.Push(kmsgItem(i, fmt.Sprint("line ", i)))
	}
	sendAll(q, 1)
	// The server confirmed 1 to 3, so a new run must send 4 and 5 again.
	q.Ack(3, nil, 10)
	got, err := s.recover([16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Rec.Msg != "line 4" || got[1].Rec.Seq != 5 || got[1].Rec.TsUsec != 50 || got[1].Kind != wire.KindKmsg {
		t.Fatalf("recovered %+v", got)
	}
	if got[0].seq != 0 {
		t.Fatal("a recovered item must be sent as new")
	}
	q.Ack(5, nil, 11)
	if got, _ := s.recover([16]byte{1}); len(got) != 0 {
		t.Fatalf("recovered %v after a full ack", msgs(got))
	}
}

func TestStashRingOverwritesOldest(t *testing.T) {
	s := memStash(10 * (entryFixed + 6))
	q := NewQueue(100)
	q.Mirror(s, tagMain)
	for i := uint64(1); i <= 25; i++ {
		q.Push(kmsgItem(i, fmt.Sprintf("line%02d", i)))
	}
	got, err := s.recover([16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	// Each entry is a tenth of the ring, so the newest 10 are left.
	if len(got) != 10 || got[0].Rec.Msg != "line16" || got[9].Rec.Msg != "line25" {
		t.Fatalf("recovered %v", msgs(got))
	}
}

func TestStashStopsAtCutEntry(t *testing.T) {
	s := memStash(MinStash)
	q := NewQueue(10)
	q.Mirror(s, tagMain)
	q.Push(kmsgItem(1, "whole"))
	q.Push(kmsgItem(2, "cut by a crash"))
	// Damage the last entry, as if the agent died while writing it.
	s.ring[entryFixed+len("whole")+entryFixed] ^= 0xff
	got, _ := s.recover([16]byte{1})
	if len(got) != 1 || got[0].Rec.Msg != "whole" {
		t.Fatalf("recovered %v", msgs(got))
	}
}

func TestStashRefusesOtherBoot(t *testing.T) {
	s := memStash(MinStash)
	q := NewQueue(10)
	q.Mirror(s, tagMain)
	q.Push(kmsgItem(1, "old boot"))
	if got, err := s.recover([16]byte{2}); err == nil || len(got) != 0 {
		t.Fatalf("records of another boot recovered: %v", msgs(got))
	}
	if _, err := newStash(make([]byte, stashHeader+MinStash), nil).recover([16]byte{1}); err != errStashFormat {
		t.Fatalf("empty memory: %v", err)
	}
}

func TestStashKeepsQueuesApart(t *testing.T) {
	s := memStash(MinStash)
	first, main := NewQueue(2), NewQueue(10)
	first.Mirror(s, tagFirst)
	main.Mirror(s, tagMain)
	first.Push(Item{Kind: wire.KindPstore, Rec: wire.Record{FileID: 7, Part: 1, Parts: 1, Msg: "pstore"}})
	main.Push(kmsgItem(1, "kmsg"))
	// Ids start at 1 in both queues: confirming the pstore line must not hide the kmsg record.
	sendAll(first, 1)
	first.Ack(1, nil, 10)
	got, _ := s.recover([16]byte{1})
	if len(got) != 1 || got[0].Rec.Msg != "kmsg" {
		t.Fatalf("recovered %v", msgs(got))
	}
}
