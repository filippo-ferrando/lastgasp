package wire

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

// Enrollment packets give an agent its key over the UDP port. Both sides derive it from an X25519
// exchange salted with the token hash, so neither the key nor the token travels.
const (
	enrollMagic   = "LGE1"
	enrollVersion = 1
)

// Enrollment answers.
const (
	EnrollOK        uint8 = 0
	EnrollBadToken  uint8 = 1 // wrong, expired, revoked or used up
	EnrollHostTaken uint8 = 2 // the host has its own line in the server key file
)

// EnrollRequest asks for a key for Host.
type EnrollRequest struct {
	Host  string
	Pub   [32]byte // X25519 public key of the agent
	Proof [32]byte // EnrollProof of the token hash, the host and Pub
}

// EnrollReply answers a request. Pub and Check are set when Status is EnrollOK.
type EnrollReply struct {
	Status uint8
	Pub    [32]byte // X25519 public key of the server
	Check  [16]byte // proves that the server derived the same key
}

// IsEnroll reports whether b is an enrollment packet.
func IsEnroll(b []byte) bool { return len(b) >= 5 && string(b[:4]) == enrollMagic }

func EncodeEnrollRequest(r *EnrollRequest) ([]byte, error) {
	if !ValidHost(r.Host) {
		return nil, ErrHost
	}
	b := append([]byte(enrollMagic), enrollVersion, byte(len(r.Host)))
	b = append(b, r.Host...)
	b = append(b, r.Pub[:]...)
	return append(b, r.Proof[:]...), nil
}

func DecodeEnrollRequest(b []byte) (EnrollRequest, error) {
	var r EnrollRequest
	if !IsEnroll(b) {
		return r, ErrMalformed
	}
	if b[4] != enrollVersion {
		return r, ErrVersion
	}
	rd := reader{b: b[5:]}
	r.Host = string(rd.take(int(rd.u8())))
	copy(r.Pub[:], rd.take(32))
	copy(r.Proof[:], rd.take(32))
	if rd.bad || len(rd.b) != 0 {
		return r, ErrMalformed
	}
	if !ValidHost(r.Host) {
		return r, ErrHost
	}
	return r, nil
}

func EncodeEnrollReply(r *EnrollReply) []byte {
	b := append([]byte(enrollMagic), enrollVersion, r.Status)
	if r.Status == EnrollOK {
		b = append(b, r.Pub[:]...)
		b = append(b, r.Check[:]...)
	}
	return b
}

func DecodeEnrollReply(b []byte) (EnrollReply, error) {
	var r EnrollReply
	if !IsEnroll(b) || len(b) < 6 {
		return r, ErrMalformed
	}
	if b[4] != enrollVersion {
		return r, ErrVersion
	}
	r.Status = b[5]
	if r.Status != EnrollOK {
		return r, nil
	}
	if len(b) != 6+32+16 {
		return r, ErrMalformed
	}
	copy(r.Pub[:], b[6:38])
	copy(r.Check[:], b[38:])
	return r, nil
}

// TokenHash is what the server keeps of a join token, and the secret both sides use while enrolling.
func TokenHash(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// EnrollProof shows that the sender knows the token, for this host and agent public key only.
func EnrollProof(tokenHash [32]byte, host string, pub [32]byte) [32]byte {
	m := hmac.New(sha256.New, tokenHash[:])
	m.Write([]byte("lastgasp enroll request " + host + " "))
	m.Write(pub[:])
	var p [32]byte
	copy(p[:], m.Sum(nil))
	return p
}

// EnrollKey derives the 32 byte agent key from the X25519 shared secret, salted with the token hash
// and bound to the host. Without the token, a key swapped on the way gives another key.
func EnrollKey(shared []byte, tokenHash [32]byte, host string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, tokenHash[:], "lastgasp enroll v1 "+host, 32)
}

// EnrollCheck is sent by the server so the agent knows both sides derived the same key.
func EnrollCheck(key []byte, host string) [16]byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("lastgasp enroll ok " + host))
	var c [16]byte
	copy(c[:], m.Sum(nil))
	return c
}
