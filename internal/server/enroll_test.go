package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"lastgasp/internal/agent"
	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

func TestEnrollEndToEnd(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	keyPath := filepath.Join(dir, "keys")
	os.WriteFile(keyPath, []byte("taken "+strings.Repeat("ab", 16)+"\n"), 0o600)
	kf, err := OpenKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keys := &Keys{File: kf, Enrolled: NewEnrolledKeys()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewMetrics(prometheus.NewRegistry(), NewTracker(), time.Minute)
	tr := NewTracker()
	in := NewIngestor(st, tr, keys, m, log)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	en := &Enroller{Store: st, Keys: keys, Log: log, Results: m.Enrollments, Reply: func(b []byte, to net.Addr) { conn.WriteTo(b, to) }}
	in.Enroller = en
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go en.Run(ctx)
	go in.Run(ctx)
	go in.Listen(conn)

	api := &API{Store: st, Tracker: tr, Gatherer: prometheus.NewRegistry(), Enrolled: keys.Enrolled,
		Install: Install{AgentAddress: conn.LocalAddr().String(), RepoURL: "https://git.example/me/lastgasp", Version: "v1.2.3"}}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/enroll-tokens", "application/json", strings.NewReader(`{"comment":"rack 4","uses":2,"ttl":"1h"}`))
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		Token, Install string
		Info           store.EnrollToken
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	want := "curl -fsSL https://git.example/me/lastgasp/releases/download/v1.2.3/install-agent.sh | sudo sh -s -- --server " +
		conn.LocalAddr().String() + " --token " + created.Token
	if resp.StatusCode != 201 || !strings.HasPrefix(created.Token, "lgj_") || created.Install != want || created.Info.UsesLeft != 2 {
		t.Fatalf("created %d %+v", resp.StatusCode, created)
	}

	enroll := func(host, token string) ([]byte, error) {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return agent.Enroll(c, conn.LocalAddr().String(), host, token)
	}
	key, err := enroll("db-01", created.Token)
	if err != nil || len(key) != 32 {
		t.Fatalf("enroll: %v", err)
	}
	// The new key is accepted at once.
	p := &wire.Packet{Host: "db-01", BootID: [16]byte{1}, Instance: 1, Seq: 1, Kind: wire.KindKmsg,
		Record: wire.Record{Priority: 3, Seq: 1, Part: 1, Parts: 1, Msg: "hello"}}
	b, _ := wire.Encode(p, key)
	in.Handle(b, nil)
	for deadline := time.Now().Add(3 * time.Second); len(tr.Snapshot()) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if len(tr.Snapshot()) != 1 {
		t.Fatal("packet with the enrolled key refused")
	}

	if _, err := enroll("db-02", "lgj_wrong"); err == nil || !strings.Contains(err.Error(), "refused the token") {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := enroll("taken", created.Token); err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("host in key file: %v", err)
	}
	if _, err := enroll("db-02", created.Token); err != nil {
		t.Fatalf("second use: %v", err)
	}
	if _, err := enroll("db-03", created.Token); err == nil {
		t.Fatal("token used more than its uses")
	}

	// A restarted server loads the enrolled keys from the database.
	again := NewEnrolledKeys()
	if err := again.Load(ctx, st); err != nil || string(again.Lookup("db-01")) != string(key) {
		t.Fatalf("reload: %v", err)
	}
	// Revoking the agent refuses its packets.
	req, _ := http.NewRequest("DELETE", srv.URL+"/api/agents/db-01", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 204 {
		t.Fatalf("revoke: %v %v", resp, err)
	}
	if keys.Lookup("db-01") != nil {
		t.Fatal("revoked key still used")
	}
	resp, _ = http.Get(srv.URL + "/api/agents")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"host":"db-02"`) || strings.Contains(string(body), "db-01") || strings.Contains(string(body), "key") {
		t.Fatalf("agents: %s", body)
	}
}

func TestEnrollerRetryAndLimits(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	tok := &store.EnrollToken{UsesLeft: 1, ExpiresAt: now.Add(time.Hour)}
	st.CreateEnrollToken(context.Background(), tok, tokenHash("lgj_once"))
	en := &Enroller{Store: st, Keys: &Keys{Enrolled: NewEnrolledKeys()}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	en.now = func() time.Time { return now }
	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 999}
	req := &wire.EnrollRequest{Host: "h", Pub: [32]byte{9}}
	req.Proof = wire.EnrollProof(wire.TokenHash("lgj_once"), "h", req.Pub)
	b, _ := wire.EncodeEnrollRequest(req)
	first := en.Handle(context.Background(), b, from)
	rep, _ := wire.DecodeEnrollReply(first)
	if rep.Status != wire.EnrollOK {
		t.Fatalf("first: %+v", rep)
	}
	// The same request again, as if the reply got lost, gets the same answer without a second use.
	now = now.Add(time.Second)
	if again := en.Handle(context.Background(), b, from); string(again) != string(first) {
		t.Fatal("retry got another answer")
	}
	// Many bad tokens from one address: it is ignored for a while.
	bad, _ := wire.EncodeEnrollRequest(&wire.EnrollRequest{Host: "h", Pub: [32]byte{8},
		Proof: wire.EnrollProof(wire.TokenHash("lgj_guess"), "h", [32]byte{8})})
	answered := 0
	for range 30 {
		now = now.Add(time.Second)
		if en.Handle(context.Background(), bad, from) != nil {
			answered++
		}
	}
	if answered != enrollBadMax {
		t.Fatalf("%d bad tokens answered", answered)
	}
	// A burst is cut by the rate limit.
	other := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 10), Port: 1}
	answered = 0
	for range 20 {
		if en.Handle(context.Background(), bad, other) != nil {
			answered++
		}
	}
	if answered != enrollBurst {
		t.Fatalf("%d of a burst answered", answered)
	}
}
