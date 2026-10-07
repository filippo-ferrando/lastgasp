package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lastgasp/internal/wire"
)

// fakeEnrollServer answers one enrollment with the key it derives from token. A server that does not
// know the real token plays a man in the middle.
func fakeEnrollServer(t *testing.T, token string, keys chan<- []byte) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 512)
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := wire.DecodeEnrollRequest(buf[:n])
		if err != nil {
			return
		}
		th := wire.TokenHash(token)
		priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		pub, _ := ecdh.X25519().NewPublicKey(req.Pub[:])
		shared, _ := priv.ECDH(pub)
		key, _ := wire.EnrollKey(shared, th, req.Host)
		rep := &wire.EnrollReply{Status: wire.EnrollOK, Check: wire.EnrollCheck(key, req.Host)}
		copy(rep.Pub[:], priv.PublicKey().Bytes())
		keys <- key
		c.WriteTo(wire.EncodeEnrollReply(rep), from)
	}()
	return c.LocalAddr().String()
}

func TestEnrollAgainstServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	keys := make(chan []byte, 1)
	key, err := Enroll(ctx, fakeEnrollServer(t, "lgj_good", keys), "db-01", "lgj_good")
	if err != nil || !bytes.Equal(key, <-keys) {
		t.Fatalf("enroll: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sub", "agent.key")
	if err := WriteKeyFile(path, key); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if parsed, err := wire.ParseKey(string(b)); err != nil || !bytes.Equal(parsed, key) {
		t.Fatalf("key file: %v", err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", st.Mode())
	}

	// A server without the token cannot make an answer the agent accepts.
	if _, err := Enroll(ctx, fakeEnrollServer(t, "lgj_guess", keys), "db-01", "lgj_good"); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("man in the middle: %v", err)
	}
}

func TestEnrollNoAnswer(t *testing.T) {
	c, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := Enroll(ctx, c.LocalAddr().String(), "db-01", "lgj_x"); err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("got %v", err)
	}
}
