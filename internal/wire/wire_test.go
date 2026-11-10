package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

var testKey = bytes.Repeat([]byte{7}, 32)

func keyFor(string) []byte { return testKey }

func samplePacket() *Packet {
	return &Packet{
		Host:     "node-1",
		BootID:   [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Instance: 42,
		Seq:      7,
		SentAt:   1700000000,
		Kind:     KindKmsg,
		Record:   Record{Priority: 3, Seq: 99, TsUsec: 123456, Part: 1, Parts: 1, Msg: "disk error"},
	}
}

func TestRoundTripRecord(t *testing.T) {
	p := samplePacket()
	b, err := Encode(p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b, keyFor)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *p {
		t.Fatalf("got %+v, want %+v", got, p)
	}
}

func TestRoundTripHeartbeat(t *testing.T) {
	p := samplePacket()
	p.Kind = KindHeartbeat
	p.Record = Record{}
	p.Stats = Stats{KmsgRead: 1, KmsgOverruns: 2, KmsgInvalid: 3, BufferDrops: 4, SendErrors: 5, PstoreRecords: 6, UptimeSec: 7, Buffered: 8}
	b, err := Encode(p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b, keyFor)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *p {
		t.Fatalf("got %+v, want %+v", got, p)
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	b, _ := Encode(samplePacket(), testKey)
	for i := range b {
		c := bytes.Clone(b)
		c[i] ^= 0x01
		if _, err := Decode(c, keyFor); err == nil {
			t.Fatalf("flipping byte %d was not detected", i)
		}
	}
}

func TestWrongKeyAndUnknownHost(t *testing.T) {
	b, _ := Encode(samplePacket(), testKey)
	other := func(string) []byte { return bytes.Repeat([]byte{9}, 32) }
	if _, err := Decode(b, other); !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if _, err := Decode(b, func(string) []byte { return nil }); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("want ErrUnknownHost, got %v", err)
	}
}

func TestSealerNeverReusesNonce(t *testing.T) {
	s, err := NewSealer(testKey, "node-1", [16]byte{1}, 42)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		b, err := s.Seal(samplePacket())
		if err != nil {
			t.Fatal(err)
		}
		hdr := string(b[:headerFixed+len("node-1")])
		if seen[hdr] {
			t.Fatalf("packet %d reuses a nonce", i)
		}
		seen[hdr] = true
		if _, err := Decode(b, keyFor); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMessageIsEncrypted(t *testing.T) {
	b, _ := Encode(samplePacket(), testKey)
	if bytes.Contains(b, []byte("disk error")) {
		t.Fatal("message found in clear text")
	}
	// Another agent run with the same key gets a different derived key.
	p := samplePacket()
	p.Instance = 43
	b2, _ := Encode(p, testKey)
	copy(b2[headerFixed+len(p.Host)-16:], b[headerFixed+len(p.Host)-16:headerFixed+len(p.Host)-8])
	if _, err := Decode(b2, keyFor); !errors.Is(err, ErrAuth) {
		t.Fatalf("instance swap: want ErrAuth, got %v", err)
	}
}

func TestOldVersionRejected(t *testing.T) {
	b, _ := Encode(samplePacket(), testKey)
	b[4] = 1
	if _, err := Decode(b, keyFor); !errors.Is(err, ErrVersion) {
		t.Fatalf("want ErrVersion, got %v", err)
	}
}

func TestTruncatedPacketRejected(t *testing.T) {
	b, _ := Encode(samplePacket(), testKey)
	for n := 0; n < len(b); n++ {
		if _, err := Decode(b[:n], keyFor); err == nil {
			t.Fatalf("truncated packet of %d bytes was accepted", n)
		}
	}
}

func TestMaxMsgFits(t *testing.T) {
	p := samplePacket()
	p.Host = strings.Repeat("h", MaxHostLen)
	p.Record.Msg = strings.Repeat("x", MaxMsg(len(p.Host)))
	agent, _ := sessionPair(t, p.Host)
	b, err := agent.Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != MaxPacket {
		t.Fatalf("packet size %d, want %d", len(b), MaxPacket)
	}
	// Version 4 has a smaller header, so the same record fits too.
	if b, err := Encode(p, testKey); err != nil || len(b) > MaxPacket {
		t.Fatalf("version 4: %d bytes, %v", len(b), err)
	}
	p.Record.Msg += "x"
	if _, err := agent.Seal(p); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestSplitMessage(t *testing.T) {
	msg := strings.Repeat("ab€", 100)
	parts := SplitMessage(msg, 10)
	if strings.Join(parts, "") != msg {
		t.Fatal("parts do not join back into the message")
	}
	for _, p := range parts {
		if len(p) > 10 || !strings.HasPrefix(msg[strings.Index(msg, p):], p) {
			t.Fatalf("bad part %q", p)
		}
		if strings.ContainsRune(p, '�') {
			t.Fatalf("part %q cuts a character", p)
		}
	}
	if got := SplitMessage("short", 10); len(got) != 1 {
		t.Fatalf("short message split into %d parts", len(got))
	}
}

func TestBootID(t *testing.T) {
	s := "0f8fad5b-d9cb-469f-a165-70867728950e"
	id, err := ParseBootID(s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if FormatBootID(id) != s {
		t.Fatalf("got %s", FormatBootID(id))
	}
	if _, err := ParseBootID("nope"); err == nil {
		t.Fatal("invalid boot id accepted")
	}
}

func TestParseKey(t *testing.T) {
	if _, err := ParseKey(strings.Repeat("ab", 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey("abcd"); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := ParseKey("zz"); err == nil {
		t.Fatal("non hex key accepted")
	}
}

func TestHostValidation(t *testing.T) {
	for _, h := range []string{"db-01", "node_1.example.net", "srv-é"} {
		if !ValidHost(h) {
			t.Errorf("%q rejected", h)
		}
	}
	for _, h := range []string{"", "a b", "a\nb", "bad\xff", strings.Repeat("h", MaxHostLen+1)} {
		if ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
		p := samplePacket()
		p.Host = h
		if _, err := Encode(p, testKey); err == nil {
			t.Errorf("encode with host %q accepted", h)
		}
	}
	// A packet with a bad host is rejected before any key lookup.
	b, _ := Encode(samplePacket(), testKey)
	b[6] = 0xff
	if _, err := Decode(b, func(string) []byte { t.Fatal("key looked up"); return nil }); !errors.Is(err, ErrHost) {
		t.Fatalf("want ErrHost, got %v", err)
	}
}

func TestAckRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	boot := [16]byte{1, 2, 3}
	beat := &Packet{Version: version, Host: "node", BootID: boot, Instance: 9, Seq: 42, SentAt: 777, Kind: KindHeartbeat}
	missing := []Range{{3, 4}, {10, 10}}
	b, err := EncodeAck(beat, 40, missing, key)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := DecodeAck(b, key, "node", boot, 9)
	if err != nil || ack.Seq != 42 || ack.SentAt != 777 || ack.Upto != 40 || len(ack.Missing) != 2 || ack.Missing[1] != (Range{10, 10}) {
		t.Fatalf("ack %+v err %v", ack, err)
	}
	if _, err := DecodeAck(b, key, "node", boot, 10); err == nil {
		t.Fatal("ack for another run accepted")
	}
	other := make([]byte, 32)
	other[0] = 1
	if _, err := DecodeAck(b, other, "node", boot, 9); err == nil {
		t.Fatal("ack with wrong key accepted")
	}
	// An ack sent back to the server must not pass as an agent packet.
	if _, err := Decode(b, func(string) []byte { return key }); err == nil {
		t.Fatal("ack decoded as agent packet")
	}
	if _, err := EncodeAck(beat, 100, make([]Range, MaxAckRanges+1), key); err == nil {
		t.Fatal("too many ranges accepted")
	}
	// Ranges out of order or above Upto are refused.
	for _, bad := range [][]Range{{{5, 4}}, {{3, 4}, {4, 6}}, {{30, 50}}} {
		b, _ := EncodeAck(beat, 40, bad, key)
		if _, err := DecodeAck(b, key, "node", boot, 9); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ranges %v: want ErrMalformed, got %v", bad, err)
		}
	}
}

func TestAckWithAllRangesFits(t *testing.T) {
	beat := &Packet{Host: strings.Repeat("h", MaxHostLen), Seq: 1, Kind: KindHeartbeat}
	missing := make([]Range, MaxAckRanges)
	for i := range missing {
		missing[i] = Range{uint64(i * 2), uint64(i * 2)}
	}
	b, err := EncodeAck(beat, 1000, missing, testKey)
	if err != nil || len(b) > MaxPacket {
		t.Fatalf("ack of %d bytes, err %v", len(b), err)
	}
}

func TestSessionAckWithAllRangesFits(t *testing.T) {
	agent, server := sessionPair(t, strings.Repeat("h", MaxHostLen))
	missing := make([]Range, MaxAckRanges)
	for i := range missing {
		missing[i] = Range{uint64(i * 2), uint64(i * 2)}
	}
	b, err := server.SealAck(&Packet{Kind: KindHeartbeat, Seq: 1}, 1000, missing)
	if err != nil || len(b) > MaxPacket {
		t.Fatalf("ack of %d bytes, err %v", len(b), err)
	}
	if a, err := agent.OpenAck(b); err != nil || len(a.Missing) != MaxAckRanges {
		t.Fatalf("ack %d ranges, err %v", len(a.Missing), err)
	}
}

func TestAckRangesByAgentVersion(t *testing.T) {
	for v, want := range map[string]int{
		"": LegacyAckRanges, "dev": LegacyAckRanges, "dev-0123abcd": LegacyAckRanges,
		"v0.1.5": LegacyAckRanges, "v0.0.9": LegacyAckRanges, "v0.1": LegacyAckRanges,
		"v0.1.6": MaxAckRanges, "v0.1.6-rc1": MaxAckRanges, "v0.2.0": MaxAckRanges, "v1.0.0-abc-dirty": MaxAckRanges,
	} {
		if got := AckRanges(v); got != want {
			t.Errorf("%q: got %d, want %d", v, got, want)
		}
	}
}

func TestVersionTwoStillAccepted(t *testing.T) {
	// Agents upgraded after the server still send version 2, without Oldest.
	p := samplePacket()
	p.Version, p.Kind, p.Record, p.Oldest = minVersion, KindHeartbeat, Record{}, 5
	b, err := Encode(p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b, keyFor)
	if err != nil || got.Version != minVersion || got.Oldest != 0 {
		t.Fatalf("got %+v err %v", got, err)
	}
	// Their acks stay version 2, which old agents can read: no receive state follows the heartbeat fields.
	ack, err := EncodeAck(got, 9, []Range{{1, 2}}, testKey)
	if err != nil || ack[4] != minVersion {
		t.Fatalf("ack version %d err %v", ack[4], err)
	}
	a, err := DecodeAck(ack, testKey, p.Host, p.BootID, p.Instance)
	if err != nil || a.Upto != 0 || a.Missing != nil {
		t.Fatalf("ack %+v err %v", a, err)
	}
}

func TestHeartbeatCarriesOldest(t *testing.T) {
	p := samplePacket()
	p.Kind, p.Record, p.Oldest = KindHeartbeat, Record{}, 1234
	b, _ := Encode(p, testKey)
	got, err := Decode(b, keyFor)
	if err != nil || got.Version != version || got.Oldest != 1234 {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestHeartbeatCarriesAgentVersion(t *testing.T) {
	p := samplePacket()
	p.Kind, p.Record, p.AgentVersion = KindHeartbeat, Record{}, "v1.4.0"
	b, _ := Encode(p, testKey)
	got, err := Decode(b, keyFor)
	if err != nil || got.Version != 4 || got.AgentVersion != "v1.4.0" {
		t.Fatalf("got %+v err %v", got, err)
	}
	// A version 3 agent gets a version 3 ack, which it can read.
	p.Version, p.AgentVersion = 3, "ignored"
	b, _ = Encode(p, testKey)
	got, err = Decode(b, keyFor)
	if err != nil || got.Version != 3 || got.AgentVersion != "" {
		t.Fatalf("v3 got %+v err %v", got, err)
	}
	ack, err := EncodeAck(got, 7, nil, testKey)
	if err != nil || ack[4] != 3 {
		t.Fatalf("ack version %d err %v", ack[4], err)
	}
	if a, err := DecodeAck(ack, testKey, p.Host, p.BootID, p.Instance); err != nil || a.Upto != 7 {
		t.Fatalf("ack %+v err %v", a, err)
	}
	// A long version is cut, so the heartbeat always fits.
	p.Version, p.AgentVersion = 0, strings.Repeat("x", 300)
	b, _ = Encode(p, testKey)
	if got, err := Decode(b, keyFor); err != nil || len(got.AgentVersion) != MaxAgentVersion {
		t.Fatalf("long version: %v %d", err, len(got.AgentVersion))
	}
}
