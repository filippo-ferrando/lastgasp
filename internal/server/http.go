package server

import (
	"embed"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"lastgasp/internal/store"
)

//go:embed ui/index.html
var uiFS embed.FS

// API serves the web UI, the JSON API and /metrics.
type API struct {
	Store      *store.Store
	Tracker    *Tracker
	StaleAfter time.Duration
	Gatherer   prometheus.Gatherer
	// Context is the number of log lines shown with an incident.
	Context int
	// Auth protects the UI and API when set. /healthz is always open, /metrics unless AuthMetrics.
	Auth        *Auth
	AuthMetrics bool
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
	view("GET /api/hosts", a.hosts)
	view("GET /api/streams", a.streams)
	view("GET /api/logs", a.logs)
	view("GET /api/download", a.download)
	view("GET /api/incidents", a.incidents)
	view("GET /api/incidents/{id}", a.incident)
	mux.Handle("POST /api/incidents/{id}/ack", a.require(RoleAdmin, http.HandlerFunc(a.ackIncident)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	metrics := promhttp.HandlerFor(a.Gatherer, promhttp.HandlerOpts{})
	if a.AuthMetrics {
		metrics = a.require(RoleViewer, metrics)
	}
	mux.Handle("GET /metrics", metrics)
	return secure(mux)
}

// secure adds headers that stop other sites from framing the UI, for example to click "acknowledge".
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Content-Security-Policy", "frame-ancestors 'none'")
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

// ackIncident needs a JSON content type, so a plain form on another site cannot call it.
func (a *API) ackIncident(w http.ResponseWriter, r *http.Request) {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := a.Store.AckIncident(r.Context(), id, time.Now()); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			code = http.StatusNotFound
		}
		http.Error(w, err.Error(), code)
		return
	}
	inc, ok := a.loadIncident(w, r)
	if ok {
		writeJSON(w, inc)
	}
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
