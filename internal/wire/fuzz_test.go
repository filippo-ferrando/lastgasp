package wire

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"testing"
)

// Fuzz tests for the parsers of untrusted packets. They run their seeds with go test,
// and search for more inputs with go test -fuzz=Name ./internal/wire.

// seeded makes the handshakes of fn the same in every process, as fuzz workers run the setup of
// a target again and must get the same seeds as the coordinator.
func seeded(fn func()) {
	old := random
	random = rand.NewChaCha8([32]byte{1})
	defer func() { random = old }()
	fn()
}

var fuzzPair struct {
	once          sync.Once
	agent, server *Session
	data, ack     []byte
}

// fuzzSessions returns one session pair for all fuzz inputs, and a valid data packet and ack.
func fuzzSessions(t testing.TB) (agent, server *Session, data, ack []byte) {
	f := &fuzzPair
	f.once.Do(func() {
		seeded(func() {
			hs, init, _ := StartHandshake(testKey, "node-1", testBoot, 42, 1)
			in, _ := ReadInit(init, keyFor)
			f.server, f.data, _ = in.Accept()
			f.agent, _ = hs.Finish(f.data)
		})
		f.data, _ = f.agent.Seal(samplePacket())
		f.ack, _ = f.server.SealAck(&Packet{Seq: 3, SentAt: 9}, 3, []Range{{1, 2}})
	})
	if f.agent == nil {
		t.Fatal("handshake failed")
	}
	return f.agent, f.server, f.data, f.ack
}

func FuzzParseHeader(f *testing.F) {
	_, _, data, ack := fuzzSessions(f)
	_, init, _ := StartHandshake(testKey, "node-1", testBoot, 42, 1)
	for _, b := range [][]byte{data, ack, init, nil, []byte("LGP1\x05")} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeader(b)
		if err != nil {
			return
		}
		if h.len > len(b) || !ValidHost(h.Host) {
			t.Fatalf("header %+v from %d bytes", h, len(b))
		}
		// A header that parses encodes back to the same bytes.
		if enc := h.encode(); !bytes.Equal(enc, b[:h.len]) {
			t.Fatalf("header does not round trip: %x vs %x", enc, b[:h.len])
		}
	})
}

func FuzzReadInit(f *testing.F) {
	var init []byte
	seeded(func() { _, init, _ = StartHandshake(testKey, "node-1", testBoot, 42, 7) })
	f.Add(init)
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := ReadInit(b, keyFor)
		if err != nil {
			return
		}
		// Only an init made with the key passes, so the fuzzer can only find the seed.
		if !bytes.Equal(b, init) {
			t.Fatalf("forged init accepted: %x", b)
		}
		if _, _, err := in.Accept(); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzFinish(f *testing.F) {
	var hs *Handshake
	var reply []byte
	seeded(func() {
		var init []byte
		hs, init, _ = StartHandshake(testKey, "node-1", testBoot, 42, 7)
		in, _ := ReadInit(init, keyFor)
		_, reply, _ = in.Accept()
	})
	f.Add(reply)
	f.Fuzz(func(t *testing.T, b []byte) {
		if bytes.Equal(b, reply) {
			return
		}
		// A failed reply leaves the handshake as it was, so the same one serves every input.
		if _, err := hs.Finish(b); err == nil {
			t.Fatalf("forged reply accepted: %x", b)
		}
	})
}

func FuzzSessionOpen(f *testing.F) {
	_, _, data, _ := fuzzSessions(f)
	f.Add(data)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, server, data, _ := fuzzSessions(t)
		p, err := server.Open(b)
		if err != nil {
			return
		}
		if !bytes.Equal(b, data) || p.Record.Msg != "disk error" {
			t.Fatalf("forged packet accepted: %x", b)
		}
	})
}

func FuzzOpenAck(f *testing.F) {
	_, _, _, ack := fuzzSessions(f)
	f.Add(ack)
	f.Fuzz(func(t *testing.T, b []byte) {
		agent, _, _, ack := fuzzSessions(t)
		a, err := agent.OpenAck(b)
		if err != nil {
			return
		}
		if !bytes.Equal(b, ack) || a.Upto != 3 {
			t.Fatalf("forged ack accepted: %x", b)
		}
	})
}

func FuzzDecode(f *testing.F) {
	b4, _ := Encode(samplePacket(), testKey)
	ack4, _ := EncodeAck(samplePacket(), 7, nil, testKey)
	f.Add(b4)
	f.Add(ack4)
	f.Fuzz(func(t *testing.T, b []byte) {
		p := samplePacket()
		Decode(b, keyFor)
		DecodeAck(b, testKey, p.Host, p.BootID, p.Instance)
	})
}

// FuzzReplayWindow compares the window with a plain set of every counter seen.
func FuzzReplayWindow(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 2})
	f.Add(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 10000), 5000))
	f.Fuzz(func(t *testing.T, b []byte) {
		var w replayWindow
		seen := map[uint64]bool{}
		var top uint64
		for ; len(b) >= 4; b = b[4:] {
			n := uint64(binary.BigEndian.Uint32(b))
			want := n != 0 && !seen[n] && n+ReplayWindow > top
			if got := w.accept(n); got != want {
				t.Fatalf("accept(%d) = %v, want %v (top %d)", n, got, want, top)
			}
			if want {
				seen[n] = true
				top = max(top, n)
			}
		}
	})
}
