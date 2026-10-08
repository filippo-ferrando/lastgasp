package wire

import (
	"bytes"
	"errors"
	"testing"
)

var testBoot = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// sessionPair runs a full handshake and returns the agent and the server side of the session.
func sessionPair(t *testing.T, host string) (agent, server *Session) {
	t.Helper()
	hs, init, err := StartHandshake(testKey, host, testBoot, 42, 1)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ReadInit(init, keyFor)
	if err != nil {
		t.Fatal(err)
	}
	server, reply, err := in.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if agent, err = hs.Finish(reply); err != nil {
		t.Fatal(err)
	}
	return agent, server
}

func TestHandshakeAndSession(t *testing.T) {
	hs, init, err := StartHandshake(testKey, "node-1", testBoot, 42, 9)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ReadInit(init, keyFor)
	if err != nil {
		t.Fatal(err)
	}
	if in.Host != "node-1" || in.BootID != testBoot || in.Instance != 42 || in.Number != 9 || in.Session != hs.Session() {
		t.Fatalf("init %+v", in)
	}
	server, reply, err := in.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) >= len(init) {
		t.Fatalf("reply of %d bytes is not smaller than the init of %d", len(reply), len(init))
	}
	agent, err := hs.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.Finish(reply); err == nil {
		t.Fatal("handshake finished twice")
	}

	p := samplePacket()
	b, err := agent.Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := server.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Record != p.Record || got.Seq != p.Seq || got.Version != VersionFS || got.Host != "node-1" {
		t.Fatalf("got %+v", got)
	}

	beat := &Packet{Kind: KindHeartbeat, Seq: 3, SentAt: 77, Oldest: 2, AgentVersion: "v9"}
	b, _ = agent.Seal(beat)
	if got, err = server.Open(b); err != nil || got.AgentVersion != "v9" || got.Oldest != 2 {
		t.Fatalf("heartbeat %+v, %v", got, err)
	}
	ackb, err := server.SealAck(got, 3, []Range{{From: 1, To: 1}})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := agent.OpenAck(ackb)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Seq != 3 || ack.SentAt != 77 || ack.Upto != 3 || len(ack.Missing) != 1 {
		t.Fatalf("ack %+v", ack)
	}
	// Each direction has its own key: an agent packet is no ack, and the other way round.
	if _, err := agent.OpenAck(b); err == nil {
		t.Fatal("agent accepted its own packet as an ack")
	}
	if _, err := server.Open(ackb); err == nil {
		t.Fatal("server accepted an ack as data")
	}
}

func TestHandshakeWrongKey(t *testing.T) {
	other := bytes.Repeat([]byte{8}, 32)
	_, init, _ := StartHandshake(other, "node-1", testBoot, 42, 1)
	if _, err := ReadInit(init, keyFor); !errors.Is(err, ErrAuth) {
		t.Fatalf("init with another key: %v", err)
	}
	if _, err := ReadInit(init, func(string) []byte { return nil }); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("init of an unknown host: %v", err)
	}

	// A changed reply is refused, and the handshake still takes the real one.
	hs, init, _ := StartHandshake(testKey, "node-1", testBoot, 42, 1)
	in, _ := ReadInit(init, keyFor)
	_, reply, _ := in.Accept()
	h, _ := ParseHeader(reply)
	for _, pos := range []int{len(reply) - 1, h.len - 1} {
		bad := bytes.Clone(reply)
		bad[pos] ^= 1
		if _, err := hs.Finish(bad); err == nil {
			t.Fatalf("reply changed at byte %d accepted", pos)
		}
	}
	if _, err := hs.Finish(reply); err != nil {
		t.Fatalf("real reply after a bad one: %v", err)
	}
}

func TestHandshakeTiedToRun(t *testing.T) {
	_, init, _ := StartHandshake(testKey, "node-1", testBoot, 42, 1)
	h, _ := ParseHeader(init)
	off := 6 + len(h.Host)
	for name, pos := range map[string]int{"host": 6, "boot": off, "instance": off + 16, "session": off + 24 + 1, "counter": off + 24 + 5} {
		b := bytes.Clone(init)
		b[pos] ^= 1
		if _, err := ReadInit(b, keyFor); err == nil {
			t.Fatalf("init with a changed %s accepted", name)
		}
	}
	for n := 0; n < len(init); n++ {
		if _, err := ReadInit(init[:n], keyFor); err == nil {
			t.Fatalf("truncated init of %d bytes accepted", n)
		}
	}
}

func TestHandshakeWipesPrivateKeys(t *testing.T) {
	hs, init, _ := StartHandshake(testKey, "node-1", testBoot, 42, 1)
	in, _ := ReadInit(init, keyFor)
	agentHS, serverHS := hs.hs, in.hs
	_, reply, _ := in.Accept()
	hs.Finish(reply)
	for name, s := range map[string][]byte{"agent": agentHS.LocalEphemeral().Private, "server": serverHS.LocalEphemeral().Private} {
		if len(s) == 0 || !bytes.Equal(s, make([]byte, len(s))) {
			t.Fatalf("%s private key not wiped", name)
		}
	}
}

func TestSessionRefusesChangedAndReplayedPackets(t *testing.T) {
	agent, server := sessionPair(t, "node-1")
	b, _ := agent.Seal(samplePacket())
	h, _ := ParseHeader(b)
	for _, pos := range []int{0, 4, 6, h.len - 13, h.len - 1, h.len, len(b) - 1} {
		c := bytes.Clone(b)
		c[pos] ^= 1
		if _, err := server.Open(c); err == nil {
			t.Fatalf("packet changed at byte %d accepted", pos)
		}
	}
	for n := 0; n < len(b); n++ {
		if _, err := server.Open(b[:n]); err == nil {
			t.Fatalf("truncated packet of %d bytes accepted", n)
		}
	}
	if _, err := server.Open(b); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(b); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}

	// A session of another handshake cannot open the packet.
	_, other := sessionPair(t, "node-1")
	b, _ = agent.Seal(samplePacket())
	if _, err := other.Open(b); err == nil {
		t.Fatal("packet opened by another session")
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	steps := []struct {
		n  uint64
		ok bool
	}{
		{0, false}, {1, true}, {1, false}, {3, true}, {2, true}, {2, false},
		{ReplayWindow + 10, true}, {11, true}, {10, false}, {3, false},
		{3 * ReplayWindow, true}, {2*ReplayWindow + 1, true}, {2 * ReplayWindow, false},
	}
	for _, s := range steps {
		if got := w.accept(s.n); got != s.ok {
			t.Fatalf("accept(%d) = %v, want %v", s.n, got, s.ok)
		}
	}
}

func TestPacketVersion(t *testing.T) {
	agent, _ := sessionPair(t, "node-1")
	b5, _ := agent.Seal(samplePacket())
	b4, _ := Encode(samplePacket(), testKey)
	if PacketVersion(b5) != VersionFS || PacketVersion(b4) != version || PacketVersion([]byte("LGE1x")) != 0 {
		t.Fatal("wrong versions")
	}
	if _, err := Decode(b5, keyFor); !errors.Is(err, ErrVersion) {
		t.Fatalf("version 4 decoder on a version 5 packet: %v", err)
	}
	if _, err := ParseHeader(b4); !errors.Is(err, ErrVersion) {
		t.Fatalf("version 5 parser on a version 4 packet: %v", err)
	}
}
