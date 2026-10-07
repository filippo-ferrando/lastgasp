package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SessionStore keeps web UI logins. The store package implements it.
type SessionStore interface {
	CreateSession(ctx context.Context, hash, user string, expires, now time.Time) error
	SessionUser(ctx context.Context, hash string, now time.Time) (string, error)
	DeleteSession(ctx context.Context, hash string) error
}

// sessionCookie holds the session token. The database only keeps its hash.
const sessionCookie = "lastgasp_session"

type sessionKey struct{}

// FromSession reports whether the request was authenticated with a session cookie.
func FromSession(ctx context.Context) bool {
	v, _ := ctx.Value(sessionKey{}).(bool)
	return v
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sessionUser returns the user of the session cookie, or nil. The user must still be in the auth file,
// so removing a user ends its sessions, and a changed role applies at once.
func (a *Auth) sessionUser(r *http.Request, users *Users) *User {
	c, err := r.Cookie(sessionCookie)
	if err != nil || a.Sessions == nil || c.Value == "" {
		return nil
	}
	name, err := a.Sessions.SessionUser(r.Context(), tokenHash(c.Value), time.Now())
	if err != nil {
		return nil
	}
	return users.byName[name]
}

func (a *Auth) setCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", Expires: expires,
		MaxAge: max(0, int(time.Until(expires).Seconds())), HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: a.SecureCookie || r.TLS != nil})
}

// Login checks a user name and password sent as JSON and starts a session. Failures count
// against the same limit as basic auth.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ipKey, nameKey := "ip:"+a.clientIP(r), "user:"+limitName(body.User)
	d := a.limit.wait(ipKey)
	if a.limit.failed(ipKey) {
		d = max(d, a.limit.wait(nameKey))
	}
	if d > 0 {
		if a.Blocked != nil {
			a.Blocked.Inc()
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds())+1))
		http.Error(w, "too many failed logins, try again later", http.StatusTooManyRequests)
		return
	}
	user := a.cur.Load().Basic(body.User, body.Password)
	if user == nil {
		a.limit.fail(ipKey, nameKey)
		if a.Failures != nil {
			a.Failures.Inc()
		}
		http.Error(w, "wrong user name or password", http.StatusUnauthorized)
		return
	}
	a.limit.reset(nameKey)
	var b [32]byte
	rand.Read(b[:])
	token := base64.RawURLEncoding.EncodeToString(b[:])
	now := time.Now()
	ttl := a.SessionTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	if err := a.Sessions.CreateSession(r.Context(), tokenHash(token), user.Name, now.Add(ttl), now); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.setCookie(w, r, token, now.Add(ttl))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"user": user.Name, "role": user.Role.String()})
}

// Logout ends the session of the cookie, if any, and clears the cookie.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" && a.Sessions != nil {
		if err := a.Sessions.DeleteSession(r.Context(), tokenHash(c.Value)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	a.setCookie(w, r, "", time.Unix(0, 0))
	w.WriteHeader(http.StatusNoContent)
}

// browser reports whether a request comes from a browser, which sends Sec-Fetch headers. Browsers get
// the login page instead of a basic auth prompt, other clients keep the WWW-Authenticate challenge.
func browser(r *http.Request) bool { return r.Header.Get("Sec-Fetch-Mode") != "" }

// loginRedirect sends a browser that opens a page without a login to the login page, and back after it.
func loginRedirect(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.Header.Get("Sec-Fetch-Mode") != "navigate" || strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	return true
}
