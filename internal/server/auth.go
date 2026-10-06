package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role is what a user may do. Viewers read everything, admins can also change incidents.
type Role int

const (
	RoleViewer Role = iota + 1
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleAdmin:
		return "admin"
	}
	return "none"
}

// ParseRole reads "viewer" or "admin".
func ParseRole(s string) (Role, error) {
	switch s {
	case "viewer":
		return RoleViewer, nil
	case "admin":
		return RoleAdmin, nil
	}
	return 0, fmt.Errorf("unknown role %q, want viewer or admin", s)
}

// User is one line of the auth file. Hash is a bcrypt hash of a password, or "sha256:<hex>" of a token.
type User struct {
	Name string
	Role Role
	hash string
}

func (u *User) token() bool { return strings.HasPrefix(u.hash, "sha256:") }

// Users is a parsed auth file.
type Users struct {
	byName map[string]*User
	tokens []*User
	// ok caches the SHA-256 of the last good password per user, so bcrypt runs once and not on every request.
	mu sync.Mutex
	ok map[string][32]byte
}

// ParseUsers reads "name role hash" lines. Empty lines and lines starting with # are ignored.
func ParseUsers(r io.Reader) (*Users, error) {
	u := &Users{byName: map[string]*User{}, ok: map[string][32]byte{}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("auth line %d: want \"name role hash\"", n)
		}
		role, err := ParseRole(f[1])
		if err != nil {
			return nil, fmt.Errorf("auth line %d: %w", n, err)
		}
		user := &User{Name: f[0], Role: role, hash: f[2]}
		switch {
		case user.token():
			if b, err := hex.DecodeString(strings.TrimPrefix(user.hash, "sha256:")); err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("auth line %d: bad sha256 hash", n)
			}
			u.tokens = append(u.tokens, user)
		case strings.HasPrefix(user.hash, "$2"):
			if _, err := bcrypt.Cost([]byte(user.hash)); err != nil {
				return nil, fmt.Errorf("auth line %d: %w", n, err)
			}
		default:
			return nil, fmt.Errorf("auth line %d: hash must be bcrypt ($2...) or sha256:<hex>", n)
		}
		if u.byName[user.Name] != nil {
			return nil, fmt.Errorf("auth line %d: %s is listed twice", n, user.Name)
		}
		u.byName[user.Name] = user
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(u.byName) == 0 {
		return nil, errors.New("auth: no user found")
	}
	return u, nil
}

// Basic checks a user name and password. A token user can also log in with its token as password.
func (u *Users) Basic(name, password string) *User {
	user := u.byName[name]
	if user == nil {
		// Same work as a real check, so the answer time does not tell which names exist.
		bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
		return nil
	}
	sum := sha256.Sum256([]byte(password))
	if user.token() {
		if hashEqual(user.hash, sum) {
			return user
		}
		return nil
	}
	u.mu.Lock()
	cached, ok := u.ok[name]
	u.mu.Unlock()
	if ok && subtle.ConstantTimeCompare(cached[:], sum[:]) == 1 {
		return user
	}
	if bcrypt.CompareHashAndPassword([]byte(user.hash), []byte(password)) != nil {
		return nil
	}
	u.mu.Lock()
	u.ok[name] = sum
	u.mu.Unlock()
	return user
}

// Bearer finds the user of an API token.
func (u *Users) Bearer(token string) *User {
	sum := sha256.Sum256([]byte(token))
	var found *User
	for _, t := range u.tokens {
		if hashEqual(t.hash, sum) && found == nil {
			found = t
		}
	}
	return found
}

var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("lastgasp"), bcrypt.DefaultCost)
	return h
})

func hashEqual(stored string, sum [32]byte) bool {
	want := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(stored, "sha256:")), []byte(want)) == 1
}

// Auth protects the HTTP handlers with the users of an auth file that can be reloaded.
type Auth struct {
	path string
	cur  atomic.Pointer[Users]
	// Failures counts rejected logins and Blocked counts requests refused by the failure limit. Both may be nil.
	Failures interface{ Inc() }
	Blocked  interface{ Inc() }
	// ProxyHeader names the header with the client address, like X-Forwarded-For, when behind a reverse proxy.
	ProxyHeader string

	limit limiter
}

// OpenAuth loads the auth file at path.
func OpenAuth(path string) (*Auth, error) {
	a := &Auth{path: path, limit: limiter{entries: map[string]*failState{}, now: time.Now}}
	if err := a.Reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// Reload reads the file again. On error the users already loaded stay in use.
func (a *Auth) Reload() error {
	f, err := os.Open(a.path)
	if err != nil {
		return err
	}
	defer f.Close()
	u, err := ParseUsers(f)
	if err != nil {
		return err
	}
	a.cur.Store(u)
	return nil
}

// Users returns the number of users and tokens loaded.
func (a *Auth) Users() int { return len(a.cur.Load().byName) }

type userKey struct{}

// UserFrom returns the user of an authenticated request, or nil when auth is off.
func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(userKey{}).(*User)
	return u
}

// Require lets a request through when it carries credentials of a user with at least the given role.
func (a *Auth) Require(min Role, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		users := a.cur.Load()
		keys := []string{"ip:" + a.clientIP(r)}
		name, pass, basic := r.BasicAuth()
		if basic {
			keys = append(keys, "user:"+name)
		}
		// A blocked client is refused before any password check, which also saves the bcrypt work.
		if d := a.limit.wait(keys...); d > 0 {
			if a.Blocked != nil {
				a.Blocked.Inc()
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds())+1))
			http.Error(w, "too many failed logins, try again later", http.StatusTooManyRequests)
			return
		}
		var user *User
		if basic {
			user = users.Basic(name, pass)
		} else if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			user = users.Bearer(strings.TrimSpace(tok))
		}
		if user == nil {
			if r.Header.Get("Authorization") != "" {
				a.limit.fail(keys...)
				if a.Failures != nil {
					a.Failures.Inc()
				}
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="lastgasp", charset="UTF-8"`)
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		// Only the user counter is cleared, so one good account cannot clear the counter of its address.
		if basic {
			a.limit.reset("user:" + name)
		}
		if user.Role < min {
			http.Error(w, "this needs the "+min.String()+" role", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
}

// me tells the UI who is logged in, so it can hide what the user may not do.
func me(w http.ResponseWriter, r *http.Request) {
	out := struct {
		User string `json:"user"`
		Role string `json:"role"`
		Auth bool   `json:"auth"`
	}{Role: RoleAdmin.String()}
	if u := UserFrom(r.Context()); u != nil {
		out.User, out.Role, out.Auth = u.Name, u.Role.String(), true
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// Loopback reports whether an HTTP listen address only accepts local connections.
func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// HashPassword returns the auth file line for a user with a password.
func HashPassword(name string, role Role, password string) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s %s", name, role, h), nil
}

// NewToken returns a random API token and its auth file line.
func NewToken(name string, role Role) (token, line string) {
	b := make([]byte, 32)
	rand.Read(b)
	token = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, fmt.Sprintf("%s %s sha256:%s", name, role, hex.EncodeToString(sum[:]))
}

// Login failure limits: after maxFails failures within failWindow, a client IP or user name is
// refused for a delay that doubles with every further failure, up to maxDelay. Nothing is locked forever.
const (
	maxFails   = 5
	failWindow = 10 * time.Minute
	firstDelay = time.Minute
	maxDelay   = 15 * time.Minute
)

type failState struct {
	fails int
	first time.Time
	until time.Time
}

// limiter counts login failures per key ("ip:..." or "user:...").
type limiter struct {
	mu      sync.Mutex
	entries map[string]*failState
	now     func() time.Time
}

func (l *limiter) state(key string, now time.Time) *failState {
	s := l.entries[key]
	if s != nil && now.Sub(s.first) > failWindow && now.After(s.until) {
		delete(l.entries, key)
		s = nil
	}
	return s
}

// wait returns how long the longest blocked key still has to wait, 0 when none is blocked.
func (l *limiter) wait(keys ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var d time.Duration
	for _, k := range keys {
		if s := l.state(k, now); s != nil && s.until.After(now) {
			d = max(d, s.until.Sub(now))
		}
	}
	return d
}

func (l *limiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) > 10000 {
		for k := range l.entries {
			l.state(k, now)
		}
	}
	for _, k := range keys {
		s := l.state(k, now)
		if s == nil {
			s = &failState{first: now}
			l.entries[k] = s
		}
		s.fails++
		if s.fails >= maxFails {
			s.until = now.Add(min(firstDelay<<(s.fails-maxFails), maxDelay))
		}
	}
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

// clientIP is the address of the caller, or the last address in ProxyHeader when it is set.
func (a *Auth) clientIP(r *http.Request) string {
	if a.ProxyHeader != "" {
		if v := r.Header.Get(a.ProxyHeader); v != "" {
			parts := strings.Split(v, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
