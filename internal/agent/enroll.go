package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lastgasp/internal/wire"
)

// Enroll asks the server at addr for a key for host, with a join token. It sends the request
// every second until an answer comes or ctx ends, as UDP may lose packets.
func Enroll(ctx context.Context, addr, host, token string) ([]byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	th := wire.TokenHash(token)
	req := &wire.EnrollRequest{Host: host}
	copy(req.Pub[:], priv.PublicKey().Bytes())
	req.Proof = wire.EnrollProof(th, host, req.Pub)
	b, err := wire.EncodeEnrollRequest(req)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	buf := make([]byte, 512)
	for {
		if _, err := c.Write(b); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if err == nil {
			rep, err := wire.DecodeEnrollReply(buf[:n])
			if err != nil {
				continue
			}
			return finishEnroll(priv, rep, th, host)
		}
		if ctx.Err() != nil {
			return nil, errors.New("no answer from the server: check the address, that UDP is open, and that the server supports enrollment")
		}
		// A refused port shows up as a read error right away, so wait before the next try.
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
}

func finishEnroll(priv *ecdh.PrivateKey, rep wire.EnrollReply, th [32]byte, host string) ([]byte, error) {
	switch rep.Status {
	case wire.EnrollOK:
	case wire.EnrollBadToken:
		return nil, errors.New("the server refused the token: wrong, expired, revoked or used up")
	case wire.EnrollHostTaken:
		return nil, fmt.Errorf("%s is taken: it has its own line in the server key file, or is enrolled already "+
			"(revoke it in the web UI first)", host)
	default:
		return nil, fmt.Errorf("the server refused the enrollment (status %d)", rep.Status)
	}
	pub, err := ecdh.X25519().NewPublicKey(rep.Pub[:])
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := wire.EnrollKey(shared, th, host)
	if err != nil {
		return nil, err
	}
	if wire.EnrollCheck(key, host) != rep.Check {
		return nil, errors.New("the answer does not match, someone may be in the middle")
	}
	return key, nil
}

// WriteKeyFile saves key as hex, readable only by its owner, replacing the file in one step.
func WriteKeyFile(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%x\n", key)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EnrollToken picks the join token from the -token value or the -token-file file, exactly one of them.
// With neither set, it reads LASTGASP_TOKEN, so the token can stay off the command line.
func EnrollToken(token, tokenFile string) (string, error) {
	switch {
	case token != "" && tokenFile != "":
		return "", errors.New("use only one of -token and -token-file")
	case tokenFile != "":
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		token = string(b)
	case token == "":
		token = os.Getenv("LASTGASP_TOKEN")
	}
	if token = strings.TrimSpace(token); token == "" {
		return "", errors.New("a join token is required: use -token, -token-file or LASTGASP_TOKEN")
	}
	return token, nil
}

// HasKey reports whether path holds a valid key.
func HasKey(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	_, err = wire.ParseKey(string(b))
	return err == nil
}
