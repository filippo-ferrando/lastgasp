package server

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

// EnrolledKeys holds the keys of enrolled agents in memory, so packets never wait for the database.
type EnrolledKeys struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewEnrolledKeys() *EnrolledKeys { return &EnrolledKeys{keys: map[string][]byte{}} }

// Load replaces the keys with those saved in the database.
func (e *EnrolledKeys) Load(ctx context.Context, st *store.Store) error {
	l, err := st.AgentKeys(ctx)
	if err != nil {
		return err
	}
	keys := map[string][]byte{}
	for _, k := range l {
		if b, err := hex.DecodeString(k.Key); err == nil {
			keys[k.Host] = b
		}
	}
	e.mu.Lock()
	e.keys = keys
	e.mu.Unlock()
	return nil
}

func (e *EnrolledKeys) Lookup(host string) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.keys[host]
}

func (e *EnrolledKeys) Set(host string, key []byte) {
	e.mu.Lock()
	e.keys[host] = key
	e.mu.Unlock()
}

func (e *EnrolledKeys) Delete(host string) {
	e.mu.Lock()
	delete(e.keys, host)
	e.mu.Unlock()
}

// Keys finds the key of a host: its own line in the key file first, then an enrolled key,
// then the "*" line. File may be nil when only enrollment is used.
type Keys struct {
	File     *KeyFile
	Enrolled *EnrolledKeys
}

func (k *Keys) Lookup(host string) []byte {
	var kr *Keyring
	if k.File != nil {
		kr = k.File.Current()
		if key := kr.Exact(host); key != nil {
			return key
		}
	}
	if k.Enrolled != nil {
		if key := k.Enrolled.Lookup(host); key != nil {
			return key
		}
	}
	if kr != nil {
		return kr.Default()
	}
	return nil
}

// Enroller answers enrollment packets: it checks the join token, derives the agent key with X25519
// and saves it. It runs apart from the packet reader, so slow database calls never hold up logs.
type Enroller struct {
	Store    *store.Store
	Keys     *Keys
	Log      *slog.Logger
	Results  *prometheus.CounterVec // by result, may be nil
	Reply    func(b []byte, to net.Addr)
	ch       chan enrollReq
	mu       sync.Mutex
	recent   map[string]recentReply // host, agent key and proof, so a lost reply is sent again without a second use
	limits   map[string]*ipLimit
	global   ipLimit // budget shared by all addresses, as source addresses can be forged
	now      func() time.Time
	initOnce sync.Once
}

type enrollReq struct {
	b    []byte
	from net.Addr
}

type recentReply struct {
	b       []byte
	expires time.Time
}

// ipLimit allows a few requests per second per address, and blocks an address after many bad tokens.
type ipLimit struct {
	tokens  float64
	last    time.Time
	bad     int
	badFrom time.Time
}

const (
	enrollRate    = 2.0 // requests per second per address
	enrollBurst   = 5
	enrollBadMax  = 10 // bad tokens per address in enrollBadSpan before it is ignored
	enrollBadSpan = 10 * time.Minute
	// A new agent enrolls once, so 20 per second still enrolls 1000 hosts in a minute.
	enrollGlobalRate  = 20.0
	enrollGlobalBurst = 40
	enrollMaxAddrs    = 10000
	recentFor         = 10 * time.Minute
)

func (e *Enroller) init() {
	e.initOnce.Do(func() {
		e.ch = make(chan enrollReq, 64)
		e.recent = map[string]recentReply{}
		e.limits = map[string]*ipLimit{}
		if e.now == nil {
			e.now = time.Now
		}
	})
}

// Submit queues an enrollment packet. It never blocks: when the queue is full the packet is dropped.
func (e *Enroller) Submit(b []byte, from net.Addr) {
	e.init()
	select {
	case e.ch <- enrollReq{append([]byte(nil), b...), from}:
	default:
		e.count("dropped")
	}
}

// Run answers queued packets until ctx is done.
func (e *Enroller) Run(ctx context.Context) {
	e.init()
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-e.ch:
			if out := e.Handle(ctx, r.b, r.from); out != nil && e.Reply != nil {
				e.Reply(out, r.from)
			}
		}
	}
}

func (e *Enroller) count(result string) {
	if e.Results != nil {
		e.Results.WithLabelValues(result).Inc()
	}
}

func addrIP(a net.Addr) string {
	if u, ok := a.(*net.UDPAddr); ok {
		return u.IP.String()
	}
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

func (l *ipLimit) blocked(now time.Time) bool {
	return l.bad >= enrollBadMax && now.Sub(l.badFrom) < enrollBadSpan
}

// take refills the budget for the time since the last call and takes one request from it.
func (l *ipLimit) take(now time.Time, rate, burst float64) bool {
	l.tokens = min(burst, l.tokens+now.Sub(l.last).Seconds()*rate)
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// allow takes one request from the budget of ip and from the shared budget, and refuses blocked addresses.
// The address goes first, so one busy address cannot use up the shared budget alone.
func (e *Enroller) allow(ip string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	l := e.limits[ip]
	if l == nil {
		if len(e.limits) >= enrollMaxAddrs {
			// Blocked addresses stay, so a spray of new addresses cannot lift their block.
			for k, o := range e.limits {
				if !o.blocked(now) {
					delete(e.limits, k)
				}
			}
		}
		l = &ipLimit{tokens: enrollBurst, last: now}
		e.limits[ip] = l
	}
	if l.blocked(now) || !l.take(now, enrollRate, enrollBurst) {
		return false
	}
	if e.global.last.IsZero() {
		e.global = ipLimit{tokens: enrollGlobalBurst, last: now}
	}
	return e.global.take(now, enrollGlobalRate, enrollGlobalBurst)
}

func (e *Enroller) badToken(ip string, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l := e.limits[ip]
	if l == nil {
		return
	}
	if now.Sub(l.badFrom) >= enrollBadSpan {
		l.bad, l.badFrom = 0, now
	}
	l.bad++
}

// Handle answers one enrollment packet. It returns nil when nothing should be sent back.
func (e *Enroller) Handle(ctx context.Context, b []byte, from net.Addr) []byte {
	e.init()
	now := e.now()
	req, err := wire.DecodeEnrollRequest(b)
	if err != nil {
		e.count("malformed")
		return nil
	}
	ip := addrIP(from)
	if !e.allow(ip, now) {
		e.count("limited")
		return nil
	}
	cacheKey := req.Host + "|" + hex.EncodeToString(req.Pub[:]) + "|" + hex.EncodeToString(req.Proof[:])
	e.mu.Lock()
	for k, r := range e.recent {
		if now.After(r.expires) {
			delete(e.recent, k)
		}
	}
	cached, ok := e.recent[cacheKey]
	e.mu.Unlock()
	if ok {
		return cached.b
	}
	// The proof tells which token the agent has, without the token on the network.
	tokens, err := e.Store.UsableEnrollTokens(ctx, now)
	if err != nil {
		e.Log.Error("enroll", "err", err)
		return nil
	}
	var tokenID int64
	var th [32]byte
	for _, t := range tokens {
		h, err := hex.DecodeString(t.Hash)
		if err != nil || len(h) != len(th) {
			continue
		}
		copy(th[:], h)
		if p := wire.EnrollProof(th, req.Host, req.Pub); hmac.Equal(p[:], req.Proof[:]) {
			tokenID = t.ID
			break
		}
	}
	badToken := func() []byte {
		e.badToken(ip, now)
		e.count("bad_token")
		e.Log.Warn("enroll refused, bad token", "host", req.Host, "from", ip)
		return wire.EncodeEnrollReply(&wire.EnrollReply{Status: wire.EnrollBadToken})
	}
	if tokenID == 0 {
		return badToken()
	}
	// Checked after the token, so only token holders learn which hosts are taken. An enrolled host
	// must be revoked first, so a token cannot take over its key.
	inFile := e.Keys.File != nil && e.Keys.File.Current().Exact(req.Host) != nil
	if inFile || e.Keys.Enrolled.Lookup(req.Host) != nil {
		e.count("host_taken")
		e.Log.Warn("enroll refused, the host has a line in the key file or is enrolled", "host", req.Host, "from", ip,
			"key_file", inFile)
		return wire.EncodeEnrollReply(&wire.EnrollReply{Status: wire.EnrollHostTaken})
	}
	agentPub, err := ecdh.X25519().NewPublicKey(req.Pub[:])
	if err != nil {
		e.count("malformed")
		return nil
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	// A weak agent key gives an all zero secret, which ECDH refuses.
	shared, err := serverKey.ECDH(agentPub)
	if err != nil {
		e.count("malformed")
		return nil
	}
	// Another enrollment may have used up the token since it was listed.
	if err := e.Store.UseEnrollToken(ctx, tokenID, now); errors.Is(err, store.ErrNotFound) {
		return badToken()
	} else if err != nil {
		e.Log.Error("enroll", "err", err)
		return nil
	}
	key, err := wire.EnrollKey(shared, th, req.Host)
	if err != nil {
		return nil
	}
	if err := e.Store.SaveAgentKey(ctx, &store.AgentKey{Host: req.Host, Key: hex.EncodeToString(key), TokenID: tokenID,
		From: ip, EnrolledAt: now}); err != nil {
		e.Log.Error("enroll: save key", "err", err)
		return nil
	}
	e.Keys.Enrolled.Set(req.Host, key)
	rep := &wire.EnrollReply{Status: wire.EnrollOK, Check: wire.EnrollCheck(key, req.Host)}
	copy(rep.Pub[:], serverKey.PublicKey().Bytes())
	out := wire.EncodeEnrollReply(rep)
	e.mu.Lock()
	e.recent[cacheKey] = recentReply{b: out, expires: now.Add(recentFor)}
	e.mu.Unlock()
	e.count("enrolled")
	e.Log.Info("agent enrolled", "host", req.Host, "from", ip, "token", tokenID)
	return out
}
