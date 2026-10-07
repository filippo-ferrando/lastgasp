package server

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"lastgasp/internal/store"
)

// Install builds the one line agent install command for a join token.
type Install struct {
	AgentAddress string // host:port agents send to, empty when unknown
	RepoURL      string // like https://git.example.net/owner/lastgasp
	Version      string // server version, the agent of the same release is installed
}

var releaseVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)

// ScriptURL is the installer of the server release, or the newest installer for development builds,
// which then installs the newest release.
func (i Install) ScriptURL() string {
	repo := strings.TrimRight(i.RepoURL, "/")
	if releaseVersion.MatchString(i.Version) {
		return repo + "/releases/download/" + i.Version + "/install-agent.sh"
	}
	return repo + "/raw/branch/main/deploy/install-agent.sh"
}

// Command is the shell line that installs and enrolls an agent with token.
func (i Install) Command(token string) string {
	addr := i.AgentAddress
	if addr == "" {
		addr = "SERVER:5140"
	}
	return "curl -fsSL " + i.ScriptURL() + " | sudo sh -s -- --server " + addr + " --token " + token
}

// AgentAddress picks the address agents send to: the flag when set, else the -public-url host with
// the port the server listens on. It returns "" when neither tells the host.
func AgentAddress(flag, publicURL, listen string) string {
	if flag != "" {
		return flag
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func (a *API) enrollTokens(w http.ResponseWriter, r *http.Request) {
	l, err := a.Store.EnrollTokens(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, l)
}

// createEnrollToken makes a join token. It is only shown in this answer, the database keeps its hash.
func (a *API) createEnrollToken(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Comment string `json:"comment"`
		Uses    int    `json:"uses"` // 0 for no limit
		TTL     string `json:"ttl"`  // default 24h
	}
	if !readJSON(w, r, &b) {
		return
	}
	ttl := 24 * time.Hour
	if b.TTL != "" {
		d, err := time.ParseDuration(b.TTL)
		if err != nil || d < time.Minute || d > 365*24*time.Hour {
			http.Error(w, "ttl must be a duration between 1m and 8760h", http.StatusBadRequest)
			return
		}
		ttl = d
	}
	if b.Uses < 0 {
		http.Error(w, "uses must be 0 (no limit) or more", http.StatusBadRequest)
		return
	}
	var raw [16]byte
	rand.Read(raw[:])
	token := "lgj_" + hex.EncodeToString(raw[:])
	now := time.Now().UTC().Truncate(time.Millisecond)
	t := store.EnrollToken{Comment: b.Comment, UsesLeft: b.Uses, ExpiresAt: now.Add(ttl), CreatedBy: userName(r), CreatedAt: now}
	if t.UsesLeft == 0 {
		t.UsesLeft = -1
	}
	if err := a.Store.CreateEnrollToken(r.Context(), &t, tokenHash(token)); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"token": token, "install": a.Install.Command(token), "agent_address": a.Install.AgentAddress,
		"info": t})
}

func (a *API) revokeEnrollToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.Store.RevokeEnrollToken(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) agents(w http.ResponseWriter, r *http.Request) {
	l, err := a.Store.AgentKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, l)
}

// revokeAgent removes the key of an enrolled host. Its packets are refused from now on.
func (a *API) revokeAgent(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	if err := a.Store.DeleteAgentKey(r.Context(), host); err != nil {
		storeError(w, err)
		return
	}
	if a.Enrolled != nil {
		a.Enrolled.Delete(host)
	}
	w.WriteHeader(http.StatusNoContent)
}
