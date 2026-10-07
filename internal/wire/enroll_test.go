package wire

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEnrollRoundTrip(t *testing.T) {
	th := TokenHash("lgj_0123456789abcdef")
	agentKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	req := &EnrollRequest{Host: "db-01"}
	copy(req.Pub[:], agentKey.PublicKey().Bytes())
	req.Proof = EnrollProof(th, req.Host, req.Pub)
	b, err := EncodeEnrollRequest(req)
	if err != nil || !IsEnroll(b) {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("lgj_")) {
		t.Fatal("the token is in the request")
	}
	got, err := DecodeEnrollRequest(b)
	if err != nil || got != *req {
		t.Fatalf("got %+v err %v", got, err)
	}
	// The proof only fits this host and public key.
	if EnrollProof(th, "db-02", got.Pub) == got.Proof || EnrollProof(TokenHash("lgj_other"), got.Host, got.Pub) == got.Proof {
		t.Fatal("proof does not depend on the host and token")
	}

	// Both sides derive the same key from their own private key and the other public key.
	serverKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub, _ := ecdh.X25519().NewPublicKey(got.Pub[:])
	shared, _ := serverKey.ECDH(pub)
	key, _ := EnrollKey(shared, th, got.Host)
	rep := &EnrollReply{Status: EnrollOK, Check: EnrollCheck(key, got.Host)}
	copy(rep.Pub[:], serverKey.PublicKey().Bytes())
	r, err := DecodeEnrollReply(EncodeEnrollReply(rep))
	if err != nil || r != *rep {
		t.Fatalf("reply %+v err %v", r, err)
	}
	spub, _ := ecdh.X25519().NewPublicKey(r.Pub[:])
	shared2, _ := agentKey.ECDH(spub)
	key2, _ := EnrollKey(shared2, th, req.Host)
	if !bytes.Equal(key, key2) || EnrollCheck(key2, req.Host) != r.Check || len(key) != 32 {
		t.Fatal("agent and server keys differ")
	}
	if other, _ := EnrollKey(shared, TokenHash("lgj_other"), got.Host); bytes.Equal(other, key) {
		t.Fatal("key does not depend on the token")
	}

	// An error reply is shorter than any request, so it cannot amplify traffic.
	if e := EncodeEnrollReply(&EnrollReply{Status: EnrollBadToken}); len(e) >= len(b) {
		t.Fatalf("error reply of %d bytes", len(e))
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(b, 0), []byte("LGE1"), []byte("LGP1xxxx")} {
		if _, err := DecodeEnrollRequest(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := EncodeEnrollRequest(&EnrollRequest{Host: "bad host"}); !errors.Is(err, ErrHost) {
		t.Fatalf("bad host: %v", err)
	}
}
