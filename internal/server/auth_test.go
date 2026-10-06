package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func authFile(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseUsers(t *testing.T) {
	alice, _ := HashPassword("alice", RoleAdmin, "secret")
	_, tok := NewToken("grafana", RoleViewer)
	if _, err := ParseUsers(strings.NewReader("# users\n\n" + alice + "\n" + tok + "\n")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "alice admin", "alice boss $2a$10$x", "alice admin plain", "x viewer sha256:zz",
		alice + "\n" + alice} {
		if _, err := ParseUsers(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUsersCheckPasswordsAndTokens(t *testing.T) {
	alice, _ := HashPassword("alice", RoleAdmin, "secret")
	token, tok := NewToken("grafana", RoleViewer)
	u, err := ParseUsers(strings.NewReader(alice + "\n" + tok))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Basic("alice", "secret"); got == nil || got.Role != RoleAdmin {
		t.Fatal("good password refused")
	}
	// The second check uses the cache and must still refuse a wrong password.
	if u.Basic("alice", "secret") == nil || u.Basic("alice", "wrong") != nil || u.Basic("bob", "secret") != nil {
		t.Fatal("wrong result after cache")
	}
	if got := u.Bearer(token); got == nil || got.Name != "grafana" {
		t.Fatal("token refused")
	}
	if u.Bearer("nope") != nil || u.Basic("grafana", "nope") != nil {
		t.Fatal("bad token accepted")
	}
	if u.Basic("grafana", token) == nil {
		t.Fatal("token as basic auth password refused")
	}
}

func TestHTTPRoles(t *testing.T) {
	alice, _ := HashPassword("alice", RoleAdmin, "a-pass")
	bob, _ := HashPassword("bob", RoleViewer, "b-pass")
	path := authFile(t, alice, bob)
	auth, err := OpenAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, filepath.Join(t.TempDir(), "db"))
	api := &API{Store: e.st, Tracker: e.tr, StaleAfter: time.Minute, Gatherer: prometheus.NewRegistry(), Auth: auth}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	do := func(method, path, user, pass string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	for _, c := range []struct {
		method, path, user, pass string
		want                     int
	}{
		{"GET", "/", "", "", 401},
		{"GET", "/api/logs", "bob", "wrong", 401},
		{"GET", "/api/logs", "bob", "b-pass", 200},
		{"GET", "/", "bob", "b-pass", 200},
		{"POST", "/api/incidents/1/ack", "bob", "b-pass", 403},
		{"POST", "/api/incidents/1/ack", "alice", "a-pass", 404}, // allowed, but no such incident
		{"GET", "/healthz", "", "", 200},
		{"GET", "/metrics", "", "", 200},
	} {
		if got := do(c.method, c.path, c.user, c.pass).StatusCode; got != c.want {
			t.Errorf("%s %s as %q: got %d, want %d", c.method, c.path, c.user, got, c.want)
		}
	}
	if do("GET", "/", "", "").Header.Get("WWW-Authenticate") == "" {
		t.Error("401 without WWW-Authenticate, the browser will not ask for a login")
	}

	req, _ := http.NewRequest("GET", srv.URL+"/api/me", nil)
	req.SetBasicAuth("bob", "b-pass")
	resp, _ := http.DefaultClient.Do(req)
	var who struct {
		User, Role string
		Auth       bool
	}
	json.NewDecoder(resp.Body).Decode(&who)
	resp.Body.Close()
	if who.User != "bob" || who.Role != "viewer" || !who.Auth {
		t.Fatalf("me: %+v", who)
	}

	// Reload drops removed users, and a broken file keeps the current ones.
	os.WriteFile(path, []byte(alice+"\n"), 0o600)
	if err := auth.Reload(); err != nil {
		t.Fatal(err)
	}
	if do("GET", "/api/logs", "bob", "b-pass").StatusCode != 401 {
		t.Fatal("removed user still allowed")
	}
	os.WriteFile(path, []byte("broken\n"), 0o600)
	if auth.Reload() == nil || do("GET", "/api/logs", "alice", "a-pass").StatusCode != 200 {
		t.Fatal("broken reload changed the users")
	}

	api.AuthMetrics = true
	srv2 := httptest.NewServer(api.Handler())
	defer srv2.Close()
	if resp, _ := http.Get(srv2.URL + "/metrics"); resp.StatusCode != 401 {
		t.Fatalf("metrics with -auth-metrics: %d", resp.StatusCode)
	}
}

func TestLoopback(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:8080": true, "[::1]:8080": true, "localhost:80": true,
		":8080": false, "0.0.0.0:8080": false, "10.0.0.1:8080": false, "bad": false} {
		if Loopback(addr) != want {
			t.Errorf("%s: want %v", addr, want)
		}
	}
}

func TestFailedLoginsAreSlowedDown(t *testing.T) {
	alice, _ := HashPassword("alice", RoleAdmin, "a-pass")
	bob, _ := HashPassword("bob", RoleViewer, "b-pass")
	auth, err := OpenAuth(authFile(t, alice, bob))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	auth.limit.now = func() time.Time { return now }
	auth.ProxyHeader = "X-Forwarded-For"
	auth.TrustedProxies, _ = ParsePrefixes("192.0.2.0/24")
	h := auth.Require(RoleViewer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	try := func(ip, user, pass string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Forwarded-For", "10.9.9.9, "+ip)
		r.SetBasicAuth(user, pass)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	fail := func(ip string) {
		t.Helper()
		for i := 0; i < maxFails; i++ {
			if code := try(ip, "alice", "guess").Code; code != 401 {
				t.Fatalf("failure %d from %s got %d", i, ip, code)
			}
		}
	}
	fail("10.0.0.1")
	// The address is blocked now, even with the right password.
	w := try("10.0.0.1", "bob", "b-pass")
	if w.Code != 429 || w.Header().Get("Retry-After") != "61" {
		t.Fatalf("blocked ip got %d retry %q", w.Code, w.Header().Get("Retry-After"))
	}
	if code := try("10.0.0.2", "bob", "b-pass").Code; code != 200 {
		t.Fatalf("other user and address got %d", code)
	}
	// alice is blocked, but only for addresses that failed too, so nobody else can lock her out.
	if code := try("10.0.0.2", "alice", "a-pass").Code; code != 200 {
		t.Fatalf("blocked user from a clean address got %d", code)
	}
	if auth.limit.wait("user:alice") != 0 {
		t.Fatal("good login did not clear the user")
	}
	fail("10.0.0.3")
	if code := try("10.0.0.4", "bob", "wrong").Code; code != 401 {
		t.Fatalf("got %d", code)
	}
	if code := try("10.0.0.4", "alice", "a-pass").Code; code != 429 {
		t.Fatalf("blocked user from a failing address got %d", code)
	}
	// The block ends, and the next failure doubles the delay.
	now = now.Add(61 * time.Second)
	if code := try("10.0.0.3", "alice", "guess").Code; code != 401 {
		t.Fatalf("after the delay got %d", code)
	}
	if d := auth.limit.wait("user:alice"); d != 2*time.Minute {
		t.Fatalf("second delay %s", d)
	}
	// After the window the counter starts over, and a good login clears the user.
	now = now.Add(failWindow + 3*time.Minute)
	if code := try("10.0.0.3", "alice", "a-pass").Code; code != 200 {
		t.Fatalf("after the window got %d", code)
	}
	if auth.limit.wait("user:alice") != 0 || len(auth.limit.entries) > 3 {
		t.Fatalf("state left: %v", auth.limit.entries)
	}
}

func TestProxyHeaderOnlyFromTrustedProxies(t *testing.T) {
	a := &Auth{ProxyHeader: "X-Forwarded-For"}
	a.TrustedProxies, _ = ParsePrefixes("10.0.0.1, 192.168.0.0/16")
	ip := func(remote, fwd string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", fwd)
		return a.clientIP(r)
	}
	if got := ip("10.0.0.1:5000", "1.2.3.4"); got != "1.2.3.4" {
		t.Fatalf("trusted proxy: %s", got)
	}
	if got := ip("8.8.8.8:5000", "1.2.3.4"); got != "8.8.8.8" {
		t.Fatalf("untrusted caller set its own address: %s", got)
	}
	if got := ip("[2001:db8::1]:5000", ""); got != "2001:db8::/64" {
		t.Fatalf("ipv6 not cut to /64: %s", got)
	}
	if _, err := ParsePrefixes("nope"); err == nil {
		t.Fatal("bad prefix accepted")
	}
}
