package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"lastgasp/internal/incident"
	"lastgasp/internal/store"
)

//go:embed ui/*.html
var uiFS embed.FS

// API serves the web UI, the JSON API and /metrics.
type API struct {
	Store      *store.Store
	Tracker    *Tracker
	StaleAfter time.Duration
	Gatherer   prometheus.Gatherer
	// Context is the number of log lines shown with an incident.
	Context int
	// Auth protects the UI and API when set. /healthz and /readyz are always open, /metrics unless AuthMetrics.
	Auth        *Auth
	AuthMetrics bool
	// Detector closes open incidents resolved by a user. Without it only closed ones can be resolved.
	Detector *incident.Detector
	// Ready reports why the server cannot work right now, for /readyz. Nil means always ready.
	Ready func(ctx context.Context) error
	// Enrolled holds the keys of enrolled agents, Install builds the install command shown for a new token.
	Enrolled *EnrolledKeys
	Install  Install
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	view := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, a.require(RoleViewer, h)) }
	view("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := uiFS.ReadFile("ui/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	view("GET /api/me", me)
	mux.HandleFunc("GET /login", a.loginPage)
	if a.Auth != nil && a.Auth.Sessions != nil {
		mux.HandleFunc("POST /api/login", a.Auth.Login)
		mux.HandleFunc("POST /api/logout", a.Auth.Logout)
	}
	view("GET /api/hosts", a.hosts)
	view("GET /api/streams", a.streams)
	view("GET /api/logs", a.logs)
	view("GET /api/download", a.download)
	view("GET /api/incidents", a.incidents)
	view("GET /api/incidents/{id}", a.incident)
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, a.require(RoleAdmin, h)) }
	admin("POST /api/incidents/{id}/ack", a.ackIncident)
	admin("POST /api/incidents/{id}/resolve", a.resolveIncident)
	view("GET /api/silences", a.silences)
	admin("POST /api/silences", a.createSilence)
	admin("DELETE /api/silences/{id}", a.endSilence)
	admin("GET /api/enroll-tokens", a.enrollTokens)
	admin("POST /api/enroll-tokens", a.createEnrollToken)
	admin("DELETE /api/enroll-tokens/{id}", a.revokeEnrollToken)
	view("GET /api/agents", a.agents)
	admin("DELETE /api/agents/{host}", a.revokeAgent)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", a.readyz)
	metrics := promhttp.HandlerFor(a.Gatherer, promhttp.HandlerOpts{})
	if a.AuthMetrics {
		metrics = a.require(RoleViewer, metrics)
	}
	mux.Handle("GET /metrics", metrics)
	return secure(mux)
}

// csp limits the UI to its own server. The pages have inline script and style, so those stay allowed.
const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'; " +
	"connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// secure adds headers that stop other sites from framing the UI, for example to click "acknowledge".
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func (a *API) require(min Role, h http.Handler) http.Handler {
	if a.Auth == nil {
		return h
	}
	return a.Auth.Require(min, h)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// HostView joins live packet counters with the boot history from the database.
type HostView struct {
	HostSummary
	Boots int `json:"boots"`
}

func (a *API) hosts(w http.ResponseWriter, r *http.Request) {
	boots := map[string]int{}
	infos, err := a.Store.Hosts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, h := range infos {
		boots[h.Host] = h.Boots
	}
	out := []HostView{}
	for _, h := range a.Tracker.Hosts(time.Now(), a.StaleAfter) {
		out = append(out, HostView{HostSummary: h, Boots: boots[h.Host]})
	}
	writeJSON(w, out)
}

// streams returns agent runs, only those with missing packets unless all=1.
func (a *API) streams(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	all := r.URL.Query().Get("all") == "1"
	out := []Stream{}
	for _, s := range a.Tracker.Snapshot() {
		if (host == "" || s.Host == host) && (all || s.Missing() > 0) {
			out = append(out, s)
		}
	}
	writeJSON(w, out)
}

func parseFilter(r *http.Request) store.Filter {
	q := r.URL.Query()
	f := store.Filter{Host: q.Get("host"), Source: q.Get("source"), Text: q.Get("q"), MaxLevel: -1}
	if v, err := strconv.Atoi(q.Get("level")); err == nil {
		f.MaxLevel = v
	}
	f.AfterID, _ = strconv.ParseInt(q.Get("after_id"), 10, 64)
	f.BeforeID, _ = strconv.ParseInt(q.Get("before_id"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	return f
}

func (a *API) logs(w http.ResponseWriter, r *http.Request) {
	recs, err := a.Store.Query(r.Context(), parseFilter(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if recs == nil {
		recs = []store.Record{}
	}
	writeJSON(w, recs)
}

// download streams every matching record as one JSON object per line, oldest first.
func (a *API) download(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)
	f.Limit = 5000
	f.BeforeID = 0
	f.Oldest = true
	name := "lastgasp"
	if f.Host != "" {
		name += "-" + f.Host
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".ndjson"}))
	enc := json.NewEncoder(w)
	for {
		recs, err := a.Store.Query(r.Context(), f)
		if err != nil {
			// The status line is already sent, so the last line tells that the file is incomplete.
			if r.Context().Err() == nil {
				enc.Encode(map[string]string{"error": "download incomplete: " + err.Error()})
			}
			return
		}
		for i := range recs {
			enc.Encode(&recs[i])
		}
		if len(recs) < f.Limit {
			return
		}
		f.AfterID = recs[len(recs)-1].ID
	}
}

func (a *API) incidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.IncidentFilter{Host: q.Get("host"), Kind: q.Get("kind"), OpenOnly: q.Get("open") == "1"}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	out, err := a.Store.Incidents(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if out == nil {
		out = []store.Incident{}
	}
	writeJSON(w, out)
}

// IncidentView is an incident with the log lines that explain it, oldest first.
type IncidentView struct {
	Incident store.Incident `json:"incident"`
	Records  []store.Record `json:"records"`
	Pstore   []store.Record `json:"pstore"`
}

func (a *API) incident(w http.ResponseWriter, r *http.Request) {
	inc, ok := a.loadIncident(w, r)
	if !ok {
		return
	}
	v := IncidentView{Incident: inc, Records: []store.Record{}, Pstore: []store.Record{}}
	n := a.Context
	if n <= 0 {
		n = 200
	}
	var err error
	if inc.LastRecordID > 0 {
		v.Records, err = a.Store.Query(r.Context(), store.Filter{Host: inc.Host, BootID: inc.BootID, Source: "kmsg",
			MaxLevel: -1, BeforeID: inc.LastRecordID + 1, Limit: n})
		for i, j := 0, len(v.Records)-1; i < j; i, j = i+1, j-1 {
			v.Records[i], v.Records[j] = v.Records[j], v.Records[i]
		}
	}
	if err == nil && (inc.Kind == "crash" || inc.Kind == "reboot") {
		v.Pstore, err = a.Store.Query(r.Context(), store.Filter{Host: inc.Host, BootID: inc.BootID, Source: "pstore",
			MaxLevel: -1, Oldest: true, Limit: 10000})
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if v.Records == nil {
		v.Records = []store.Record{}
	}
	if v.Pstore == nil {
		v.Pstore = []store.Record{}
	}
	writeJSON(w, v)
}

// loginPage shows the login form, or goes to the UI when there is no login to do.
func (a *API) loginPage(w http.ResponseWriter, r *http.Request) {
	if a.Auth == nil || a.Auth.Sessions == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	b, _ := uiFS.ReadFile("ui/login.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// readyz answers 200 when the database and the packet path work, 503 otherwise. The reason goes
// to the log only, as /readyz needs no login and database errors can name hosts and users.
func (a *API) readyz(w http.ResponseWriter, r *http.Request) {
	if a.Ready != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := a.Ready(ctx); err != nil {
			slog.Warn("not ready", "err", err)
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
	}
	w.Write([]byte("ok\n"))
}

// readJSON decodes a small JSON body. The JSON content type is required, so a plain form on another
// site cannot call the API. An empty body leaves v as it is.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v)
	if err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// userName is the logged in user, or "admin" when there is no login.
func userName(r *http.Request) string {
	if u := UserFrom(r.Context()); u != nil {
		return u.Name
	}
	return "admin"
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
	}
	return id, err == nil
}

func storeError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if errors.Is(err, store.ErrNotFound) {
		code = http.StatusNotFound
	}
	http.Error(w, err.Error(), code)
}

// noteBody is the optional body of ack and resolve.
type noteBody struct {
	Note string `json:"note"`
}

func (a *API) ackIncident(w http.ResponseWriter, r *http.Request) {
	var b noteBody
	if !readJSON(w, r, &b) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.Store.AckIncident(r.Context(), id, userName(r), b.Note, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	if inc, ok := a.loadIncident(w, r); ok {
		writeJSON(w, inc)
	}
}

// resolveIncident closes an incident by hand, for example after a fix, and sends resolve alerts.
func (a *API) resolveIncident(w http.ResponseWriter, r *http.Request) {
	var b noteBody
	if !readJSON(w, r, &b) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var err error
	if a.Detector != nil {
		err = a.Detector.Resolve(r.Context(), id, userName(r), b.Note, time.Now())
	} else {
		err = a.Store.ResolveIncident(r.Context(), id, userName(r), b.Note, time.Now())
	}
	switch {
	case errors.Is(err, incident.ErrRebootPending), errors.Is(err, incident.ErrSilentOpen):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "incident not found or still open", http.StatusNotFound)
		return
	case err != nil:
		storeError(w, err)
		return
	}
	if inc, ok := a.loadIncident(w, r); ok {
		writeJSON(w, inc)
	}
}

// silences lists active and upcoming silences, and those that ended in the last day with all=1.
func (a *API) silences(w http.ResponseWriter, r *http.Request) {
	since := time.Now()
	if r.URL.Query().Get("all") == "1" {
		since = since.Add(-incident.MaxAlertAge)
	}
	out, err := a.Store.Silences(r.Context(), since)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, out)
}

// silenceBody creates a silence: from starts_at (default now) until ends_at, or for duration.
type silenceBody struct {
	Host     string    `json:"host"`
	Kind     string    `json:"kind"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
	Duration string    `json:"duration"`
	Comment  string    `json:"comment"`
}

func (a *API) createSilence(w http.ResponseWriter, r *http.Request) {
	var b silenceBody
	if !readJSON(w, r, &b) {
		return
	}
	now := time.Now()
	sl := store.Silence{Host: b.Host, Kind: b.Kind, StartsAt: b.StartsAt, EndsAt: b.EndsAt, Comment: b.Comment,
		CreatedBy: userName(r), CreatedAt: now}
	if sl.StartsAt.IsZero() {
		sl.StartsAt = now
	}
	if b.Duration != "" {
		d, err := time.ParseDuration(b.Duration)
		if err != nil {
			http.Error(w, "bad duration: "+err.Error(), http.StatusBadRequest)
			return
		}
		sl.EndsAt = sl.StartsAt.Add(d)
	}
	if sl.Kind != "" && !slices.Contains(incident.Kinds(), sl.Kind) {
		http.Error(w, "unknown incident kind "+strconv.Quote(sl.Kind), http.StatusBadRequest)
		return
	}
	// The database keeps milliseconds, and the API answers in UTC.
	for _, t := range []*time.Time{&sl.StartsAt, &sl.EndsAt, &sl.CreatedAt} {
		*t = t.UTC().Truncate(time.Millisecond)
	}
	if err := store.ValidSilence(&sl); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Store.CreateSilence(r.Context(), &sl); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, sl)
}

// endSilence ends a silence now. It stays listed until it is a day old.
func (a *API) endSilence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.Store.EndSilence(r.Context(), id, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) loadIncident(w http.ResponseWriter, r *http.Request) (store.Incident, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return store.Incident{}, false
	}
	inc, err := a.Store.GetIncident(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "incident not found", http.StatusNotFound)
		return inc, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return inc, false
	}
	return inc, true
}
