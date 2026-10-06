package incident

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"lastgasp/internal/store"
)

func TestDefaultRules(t *testing.T) {
	r := DefaultRules()
	for msg, want := range map[string]string{
		"Kernel panic - not syncing: Fatal exception":                         "panic",
		"Oops: general protection fault, probably for non-canonical address":  "oops",
		"BUG: kernel NULL pointer dereference, address: 0000000000000008":     "bug",
		"watchdog: BUG: soft lockup - CPU#3 stuck for 22s! [kworker/3:1:123]": "lockup",
		"Out of memory: Killed process 1234 (java) total-vm:1234kB":           "oom",
		"blk_update_request: I/O error, dev sda, sector 2048 op 0x0:(READ)":   "io_error",
		"EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2":         "fs_error",
		"mce: [Hardware Error]: Machine check events logged":                  "mce",
		"INFO: task jbd2/sda1-8:312 blocked for more than 120 seconds.":       "hung_task",
		"usb 1-1: new high-speed USB device number 2 using xhci_hcd":          "",
	} {
		got := ""
		if m := r.Match(msg); m != nil {
			got = m.Name
		}
		if got != want {
			t.Errorf("%q matched %q, want %q", msg, got, want)
		}
	}
}

func TestParseRules(t *testing.T) {
	r, err := ParseRules(strings.NewReader("# local rules\noom off\nio_error critical I/O error\nraid warning md/raid.*: Disk failure\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m := r.Match("Out of memory: Killed process 1"); m != nil {
		t.Fatalf("oom should be off, matched %s", m.Name)
	}
	if m := r.Match("Buffer I/O error on dev sdb"); m == nil || m.Severity != store.SeverityCritical {
		t.Fatalf("io_error not replaced: %+v", m)
	}
	if m := r.Match("md/raid1:md0: Disk failure on sdb1"); m == nil || m.Name != "raid" {
		t.Fatal("new rule not added")
	}
	for _, bad := range []string{"x", "x loud abc", "x warning (", "x warning"} {
		if _, err := ParseRules(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

type env struct {
	st  *store.Store
	d   *Detector
	t0  time.Time
	seq int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	m := NewMetrics(prometheus.NewRegistry())
	d := NewDetector(st, DefaultRules(), Config{SilentAfter: time.Minute, CrashWait: time.Minute, Context: 50}, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &env{st: st, d: d, t0: time.Now().Truncate(time.Second)}
}

// add stores records like the ingestor does and passes them to the detector.
func (e *env) add(t *testing.T, host, boot, source string, now time.Time, msgs ...string) {
	t.Helper()
	var recs []*store.Record
	for _, m := range msgs {
		e.seq++
		recs = append(recs, &store.Record{Host: host, BootID: boot, Source: source, Message: m, Part: 1, Parts: 1,
			ReceivedAt: now, DedupKey: source + string(rune(e.seq)) + m, ContentKey: m})
	}
	ins, err := e.st.InsertBatch(context.Background(), recs)
	if err != nil {
		t.Fatal(err)
	}
	// pstore lines of an old boot are sent from the new boot, so they do not count as seen.
	if source == "kmsg" {
		e.d.Seen(host, boot, now)
	}
	e.d.Records(context.Background(), recs, ins, now)
}

func (e *env) incidents(t *testing.T) []store.Incident {
	t.Helper()
	e.d.Tick(context.Background(), time.Time{}.Add(1)) // saves changes only, as nothing is old at time zero
	l, err := e.st.Incidents(context.Background(), store.IncidentFilter{})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func withoutSilent(l []store.Incident) []store.Incident {
	var out []store.Incident
	for _, i := range l {
		if i.Kind != KindSilent {
			out = append(out, i)
		}
	}
	return out
}

func TestKernelErrorsAreGrouped(t *testing.T) {
	e := newEnv(t)
	e.add(t, "h", "b1", "kmsg", e.t0, "boot ok", "blk_update_request: I/O error, dev sda, sector 1")
	e.add(t, "h", "b1", "kmsg", e.t0, "blk_update_request: I/O error, dev sda, sector 2", "Kernel panic - not syncing: x")
	l := e.incidents(t)
	if len(l) != 2 {
		t.Fatalf("got %+v", l)
	}
	panic, io := l[0], l[1]
	if panic.Rule != "panic" || panic.Severity != store.SeverityCritical || io.Rule != "io_error" || io.Count != 2 || io.LastRecordID <= io.FirstRecordID {
		t.Fatalf("got %+v", l)
	}
}

func TestSilentHostOpensAndCloses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "last words")
	e.d.Tick(ctx, e.t0.Add(30*time.Second))
	if l := e.incidents(t); len(l) != 0 {
		t.Fatalf("too early: %+v", l)
	}
	e.d.Tick(ctx, e.t0.Add(2*time.Minute))
	e.d.Tick(ctx, e.t0.Add(3*time.Minute))
	l := e.incidents(t)
	if len(l) != 1 || l[0].Kind != KindSilent || !l[0].Open() || !strings.Contains(l[0].Summary, "last words") {
		t.Fatalf("got %+v", l)
	}
	e.d.Seen("h", "b1", e.t0.Add(4*time.Minute))
	if l := e.incidents(t); l[0].Open() || !strings.Contains(l[0].Summary, "sent again") {
		t.Fatalf("not closed: %+v", l[0])
	}
}

func TestRebootWithPstoreIsCrash(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "all fine")
	e.d.NewBoot(ctx, "h", "b2", "b1", e.t0.Add(time.Minute))
	// pstore lines of boot 1 arrive after the first packets of boot 2.
	e.add(t, "h", "b1", "pstore", e.t0.Add(time.Minute), "all fine", "Kernel panic - not syncing: Fatal exception")
	e.d.Tick(ctx, e.t0.Add(90*time.Second))
	if l := e.incidents(t); l[0].Kind != KindReboot || !l[0].Open() {
		t.Fatalf("decided too early: %+v", l)
	}
	e.d.Tick(ctx, e.t0.Add(3*time.Minute))
	l := withoutSilent(e.incidents(t))
	if len(l) != 1 || l[0].Kind != KindCrash || l[0].Rule != "panic" || l[0].Open() || l[0].BootID != "b1" {
		t.Fatalf("got %+v", l)
	}
}

func TestRebootWithPanicInTailIsCrash(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "BUG: unable to handle page fault", "Call Trace:")
	e.d.NewBoot(ctx, "h", "b2", "b1", e.t0.Add(time.Minute))
	e.d.Tick(ctx, e.t0.Add(3*time.Minute))
	l := e.incidents(t)
	var crash *store.Incident
	for i := range l {
		if l[i].Kind == KindCrash {
			crash = &l[i]
		}
		if l[i].Kind == KindKernelError && l[i].Open() {
			t.Fatal("kernel error of the old boot not closed")
		}
	}
	if crash == nil || crash.Rule != "bug" {
		t.Fatalf("got %+v", l)
	}
}

func TestPlainReboot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "systemd-shutdown: Syncing filesystems")
	e.d.NewBoot(ctx, "h", "b2", "b1", e.t0.Add(time.Minute))
	e.d.NewBoot(ctx, "other", "x", "", e.t0.Add(time.Minute)) // first boot ever, nothing to report
	e.d.Tick(ctx, e.t0.Add(3*time.Minute))
	l := withoutSilent(e.incidents(t))
	if len(l) != 1 || l[0].Kind != KindReboot || l[0].Severity != store.SeverityInfo || l[0].Open() {
		t.Fatalf("got %+v", l)
	}
}

func TestLoadRestoresOpenIncidents(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "x")
	e.d.Tick(ctx, e.t0.Add(2*time.Minute))
	// A new detector, as after a server restart, must not open a second silent incident.
	d2 := NewDetector(e.st, DefaultRules(), e.d.cfg, e.d.Metrics, e.d.Log)
	if err := d2.Load(ctx, []HostSeen{{Host: "h", BootID: "b1"}}, e.t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	d2.Tick(ctx, e.t0.Add(10*time.Minute))
	if l := e.incidents(t); len(l) != 1 {
		t.Fatalf("got %d incidents", len(l))
	}
	d2.Seen("h", "b1", e.t0.Add(11*time.Minute))
	if l := e.incidents(t); l[0].Open() {
		t.Fatal("restored incident not closed")
	}
	// Forgotten hosts do not turn silent.
	d2.Forget(e.t0.Add(time.Hour))
	d2.Tick(ctx, e.t0.Add(2*time.Hour))
	if l := e.incidents(t); len(l) != 1 {
		t.Fatalf("got %d incidents after forget", len(l))
	}
}

type hook struct {
	mu     sync.Mutex
	fails  int
	status int // answer for failures, 503 when 0
	bodies []string
	sigs   []string
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fails > 0 {
		h.fails--
		http.Error(w, "busy", cmp.Or(h.status, http.StatusServiceUnavailable))
		return
	}
	b, _ := io.ReadAll(r.Body)
	h.bodies = append(h.bodies, string(b))
	h.sigs = append(h.sigs, r.Header.Get("X-Lastgasp-Signature"))
}

func TestNotifier(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &hook{fails: 1}
	srv := httptest.NewServer(h)
	defer srv.Close()
	key := []byte("0123456789abcdef")
	n := &Notifier{Store: e.st, Name: "hook", URL: srv.URL, Key: key, PublicURL: "https://lg.example/", MinSeverity: store.SeverityWarning,
		RateLimit: time.Hour, Metrics: e.d.Metrics, Log: e.d.Log}
	n.init()

	e.add(t, "h", "b1", "kmsg", e.t0, "Kernel panic - not syncing: x", "Out of memory: Killed process 1", "EXT4-fs error (device sda1)")
	e.add(t, "h", "b1", "kmsg", e.t0, "BUG: soft")                     // another rule, so not held back by the panic alert
	e.add(t, "h", "b2", "kmsg", e.t0, "Kernel panic - not syncing: y") // same rule again, rate limited
	if err := n.flush(ctx); err == nil {
		t.Fatal("first call should fail")
	}
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.bodies) != 4 {
		t.Fatalf("sent %d alerts, want 4", len(h.bodies))
	}
	var p Payload
	if err := json.Unmarshal([]byte(h.bodies[0]), &p); err != nil {
		t.Fatal(err)
	}
	if p.Incident.Rule != "panic" || !strings.HasPrefix(p.Text, "[critical] h kernel error (panic)") || p.URL != "https://lg.example/#incident=1" {
		t.Fatalf("payload %+v", p)
	}
	if h.sigs[0] != "sha256="+Sign(key, []byte(h.bodies[0])) {
		t.Fatal("bad signature")
	}
	l, _ := e.st.Incidents(ctx, store.IncidentFilter{})
	states := map[string]string{}
	for _, i := range l {
		states[i.BootID+" "+i.Rule] = alertOf(i, "hook")
	}
	if states["b1 panic"] != store.AlertSent || states["b1 bug"] != store.AlertSent || states["b1 oom"] != store.AlertSent ||
		states["b2 panic"] != store.AlertSuppressed {
		t.Fatalf("alert states %v", states)
	}
}

func TestNotifierGivesUpSoOneAlertCannotBlockOthers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		fails  int
		calls  int
	}{
		{"permanent error", http.StatusBadRequest, 1, 1},
		{"retries used up", http.StatusServiceUnavailable, maxTries, maxTries},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			h := &hook{fails: tc.fails, status: tc.status}
			srv := httptest.NewServer(h)
			defer srv.Close()
			n := &Notifier{Store: e.st, Name: "hook", URL: srv.URL, MinSeverity: store.SeverityWarning, Metrics: e.d.Metrics, Log: e.d.Log}
			n.init()
			e.add(t, "h", "b1", "kmsg", e.t0, "Kernel panic - not syncing: x")
			e.add(t, "h", "b1", "kmsg", e.t0, "BUG: soft")
			var err error
			for i := 0; i < tc.calls; i++ {
				err = n.flush(context.Background())
			}
			if err != nil || len(h.bodies) != 1 {
				t.Fatalf("err %v, sent %d", err, len(h.bodies))
			}
			l, _ := e.st.Incidents(context.Background(), store.IncidentFilter{})
			for _, i := range l {
				want := map[string]string{"panic": store.AlertFailed, "bug": store.AlertSent}[i.Rule]
				if got := alertOf(i, "hook"); got != want {
					t.Fatalf("%s: %s, want %s", i.Rule, got, want)
				}
			}
		})
	}
}

func TestNotifierSlackFormat(t *testing.T) {
	e := newEnv(t)
	h := &hook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	n := &Notifier{Store: e.st, Name: "hook", URL: srv.URL, Format: "slack", Metrics: e.d.Metrics, Log: e.d.Log}
	n.init()
	e.add(t, "h", "b1", "kmsg", e.t0, "Kernel panic - not syncing: x")
	if err := n.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	json.Unmarshal([]byte(h.bodies[0]), &body)
	if len(body) != 1 || !strings.Contains(body["text"], "Kernel panic") || h.sigs[0] != "" {
		t.Fatalf("body %v sig %q", body, h.sigs[0])
	}
}

func TestNotifierRunSendsOnWake(t *testing.T) {
	e := newEnv(t)
	h := &hook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	n := &Notifier{Store: e.st, Name: "hook", URL: srv.URL, Metrics: e.d.Metrics, Log: e.d.Log}
	e.d.Wake = n.Wake
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	e.add(t, "h", "b1", "kmsg", e.t0, "Kernel panic - not syncing: x")
	deadline := time.Now().Add(3 * time.Second)
	for {
		h.mu.Lock()
		got := len(h.bodies)
		h.mu.Unlock()
		if got == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("alert not sent after wake")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLatePstoreTurnsRebootIntoCrash(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "all fine")
	e.d.NewBoot(ctx, "h", "b2", "b1", e.t0.Add(time.Minute))
	e.d.Tick(ctx, e.t0.Add(3*time.Minute))
	l := withoutSilent(e.incidents(t))
	if len(l) != 1 || l[0].Kind != KindReboot {
		t.Fatalf("got %+v", l)
	}
	e.st.SetAlert(ctx, l[0].ID, "hook", store.AlertSent, e.t0)

	// After a server restart, the pstore lines finally arrive.
	d2 := NewDetector(e.st, DefaultRules(), e.d.cfg, e.d.Metrics, e.d.Log)
	if err := d2.Load(ctx, []HostSeen{{Host: "h", BootID: "b2"}}, e.t0.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.d = d2
	e.add(t, "h", "b1", "pstore", e.t0.Add(5*time.Minute), "Oops: 0000 [#1] SMP")
	got, _ := e.st.GetIncident(ctx, l[0].ID)
	if got.Kind != KindCrash || got.Rule != "oops" || len(got.Alerts) != 0 {
		t.Fatalf("got %+v", got)
	}
	// A later boot means pstore lines belong to another boot, so nothing changes.
	e.d.NewBoot(ctx, "h", "b3", "b2", e.t0.Add(6*time.Minute))
	e.add(t, "h", "b1", "pstore", e.t0.Add(7*time.Minute), "more")
	if n := len(withoutSilent(e.incidents(t))); n != 2 {
		t.Fatalf("got %d incidents", n)
	}
}

func TestSilentHostResolveAlert(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &hook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	n := &Notifier{Store: e.st, Name: "hook", URL: srv.URL, MinSeverity: store.SeverityWarning, RateLimit: time.Hour, Metrics: e.d.Metrics, Log: e.d.Log}
	n.init()
	e.add(t, "h", "b1", "kmsg", e.t0, "last words")
	e.d.Tick(ctx, e.t0.Add(2*time.Minute))
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	e.d.Seen("h", "b1", e.t0.Add(3*time.Minute))
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.bodies) != 2 {
		t.Fatalf("sent %d alerts, want 2", len(h.bodies))
	}
	var p Payload
	json.Unmarshal([]byte(h.bodies[1]), &p)
	if !p.Resolved || !strings.HasPrefix(p.Text, "[resolved] h is sending again") {
		t.Fatalf("resolve payload %+v", p)
	}
	l, _ := e.st.Incidents(ctx, store.IncidentFilter{})
	if alertOf(l[0], "hook") != store.AlertResolved {
		t.Fatalf("alert states %v", l[0].Alerts)
	}
}

func alertOf(i store.Incident, target string) string {
	for _, a := range i.Alerts {
		if a.Target == target {
			return a.State
		}
	}
	return ""
}

func TestKernelErrorResolvesAfterQuietPeriod(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.d.cfg.ResolveAfter = 30 * time.Minute
	e.add(t, "h", "b1", "kmsg", e.t0, "Out of memory: Killed process 1")
	e.d.Seen("h", "b1", e.t0.Add(20*time.Minute))
	e.d.Tick(ctx, e.t0.Add(20*time.Minute))
	if l := e.incidents(t); !l[0].Open() {
		t.Fatal("resolved too early")
	}
	e.d.Seen("h", "b1", e.t0.Add(31*time.Minute))
	e.d.Tick(ctx, e.t0.Add(31*time.Minute))
	l := e.incidents(t)
	if l[0].Open() || !l[0].Resolved || !strings.Contains(l[0].Summary, "(no new matching line for") {
		t.Fatalf("got %+v", l[0])
	}
}

func TestCleanRebootResolvesOldBoot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "blk_update_request: I/O error, dev sda, sector 1")
	e.d.NewBoot(ctx, "h", "b2", "b1", e.t0.Add(time.Minute))
	e.d.Tick(ctx, e.t0.Add(3*time.Minute))
	for _, i := range withoutSilent(e.incidents(t)) {
		if i.Kind == KindKernelError && !i.Resolved {
			t.Fatalf("kernel error not resolved by a clean reboot: %+v", i)
		}
	}
	// A crash does not resolve the errors that led to it.
	e.add(t, "h", "b2", "kmsg", e.t0.Add(4*time.Minute), "blk_update_request: I/O error, dev sdb, sector 1", "Kernel panic - not syncing: x")
	e.d.NewBoot(ctx, "h", "b3", "b2", e.t0.Add(5*time.Minute))
	e.d.Tick(ctx, e.t0.Add(8*time.Minute))
	for _, i := range e.incidents(t) {
		if i.BootID == "b2" && i.Kind == KindKernelError && i.Resolved {
			t.Fatalf("kernel error resolved by a crash: %+v", i)
		}
	}
}

func TestTargetsAreIndependent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok, bad := &hook{}, &hook{fails: 100}
	s1, s2 := httptest.NewServer(ok), httptest.NewServer(bad)
	defer s1.Close()
	defer s2.Close()
	def := &Notifier{Store: e.st, Format: "json", MinSeverity: store.SeverityWarning, Metrics: e.d.Metrics, Log: e.d.Log}
	chat, err := ParseTarget("name=chat,format=slack,url="+s1.URL, def)
	if err != nil {
		t.Fatal(err)
	}
	pager, err := ParseTarget("name=pager,min=critical,url="+s2.URL, def)
	if err != nil {
		t.Fatal(err)
	}
	chat.init()
	pager.init()
	e.add(t, "h", "b1", "kmsg", e.t0, "Out of memory: Killed process 1", "Kernel panic - not syncing: x")
	if err := chat.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pager.flush(ctx); err == nil {
		t.Fatal("pager should fail")
	}
	if len(ok.bodies) != 2 {
		t.Fatalf("chat got %d alerts", len(ok.bodies))
	}
	// The failing target keeps its alert pending; the working one is done.
	if p, _ := e.st.PendingAlerts(ctx, "pager", store.SeverityCritical, e.t0.Add(-time.Hour), 10); len(p) != 1 {
		t.Fatalf("pager pending %d", len(p))
	}
	if p, _ := e.st.PendingAlerts(ctx, "chat", store.SeverityWarning, e.t0.Add(-time.Hour), 10); len(p) != 0 {
		t.Fatalf("chat pending %d", len(p))
	}
}

func TestParseTarget(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key")
	os.WriteFile(key, []byte(strings.Repeat("ab", 16)), 0o600)
	def := &Notifier{Format: "json", MinSeverity: store.SeverityWarning, RateLimit: time.Minute}
	n, err := ParseTarget("https://hooks.slack.com/services/T/B/secret", def)
	if err != nil || n.Name != "hooks.slack.com" || n.Format != "json" || n.RateLimit != time.Minute {
		t.Fatalf("plain url: %+v %v", n, err)
	}
	n, err = ParseTarget("name=ops,format=slack,min=critical,key-file="+key+",rate=1h,url=https://x.example/a?b=1,c=2", def)
	if err != nil || n.Name != "ops" || n.Format != "slack" || n.MinSeverity != store.SeverityCritical ||
		n.RateLimit != time.Hour || len(n.Key) != 16 || n.URL != "https://x.example/a?b=1,c=2" {
		t.Fatalf("options: %+v %v", n, err)
	}
	for _, bad := range []string{"", "ftp://x", "name=a", "name=a,url=nope", "loud=1,url=https://x", "min=huge,url=https://x",
		"format=xml,url=https://x", "key-file=/missing,url=https://x"} {
		if _, err := ParseTarget(bad, def); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func newHook(t *testing.T, h *hook) string {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestCrashCheckWaitsForDatabase(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.add(t, "h", "b1", "kmsg", e.t0, "Kernel panic - not syncing: x")
	e.d.NewBoot(ctx, "h", "b2", "b1", e.t0.Add(time.Minute))
	// A failing query must not turn the crash into a clean reboot.
	broken, cancel := context.WithCancel(ctx)
	cancel()
	e.d.Tick(broken, e.t0.Add(3*time.Minute))
	if e.d.open[openKey("h", "b1", KindReboot, "")] == nil {
		t.Fatal("reboot closed although the crash check failed")
	}
	e.d.Tick(ctx, e.t0.Add(4*time.Minute))
	var crash bool
	for _, i := range withoutSilent(e.incidents(t)) {
		crash = crash || i.Kind == KindCrash
	}
	if !crash {
		t.Fatal("crash not found after the database came back")
	}
}
