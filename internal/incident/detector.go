package incident

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"lastgasp/internal/store"
)

// Incident kinds.
const (
	KindCrash       = "crash"
	KindReboot      = "reboot"
	KindSilent      = "silent"
	KindKernelError = "kernel_error"
)

var kinds = []string{KindCrash, KindReboot, KindSilent, KindKernelError}

// Config tunes the detector.
type Config struct {
	SilentAfter time.Duration // time without packets before a host counts as silent
	CrashWait   time.Duration // time after a reboot to wait for pstore lines before deciding crash or reboot
	Context     int           // number of log lines kept as context of an incident
	// ResolveAfter closes a kernel error incident as resolved when no new line matched for this long, 0 never.
	ResolveAfter time.Duration
}

// Metrics are the incident Prometheus metrics.
type Metrics struct {
	Created *prometheus.CounterVec
	Open    *prometheus.GaugeVec
	Alerts  *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Created: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lastgasp_incidents_total", Help: "Incidents found. A reboot that turns out to be a crash counts in both kinds.",
		}, []string{"host", "kind"}),
		Open: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lastgasp_incidents_open", Help: "Incidents still going on.",
		}, []string{"kind"}),
		Alerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lastgasp_alerts_total", Help: "Incident alerts by target and result (sent, resolved, failed, suppressed).",
		}, []string{"target", "result"}),
	}
	reg.MustRegister(m.Created, m.Open, m.Alerts)
	return m
}

// HostSeen is the last known state of a host, used to restore the detector after a server restart.
type HostSeen struct {
	Host   string
	BootID string
}

type hostState struct {
	boot     string
	lastSeen time.Time
	silent   bool // a silent incident may be open, so the next packet must close it
}

// Detector turns packets and stored records into incidents. It is safe for concurrent use.
// Database queries run without mu held, so the ingest worker never waits for a slow query of Tick.
type Detector struct {
	Store   *store.Store
	Log     *slog.Logger
	Metrics *Metrics
	// Wake is called when an incident may need an alert.
	Wake func()

	cfg   Config
	rules atomic.Pointer[Rules]
	// hmu guards hosts. It is taken for every packet and never held during database calls.
	// When both are needed, mu is taken first.
	hmu   sync.Mutex
	hosts map[string]*hostState
	mu    sync.Mutex
	open  map[string]*store.Incident
	dirty map[int64]*store.Incident
	// lastReboot is the newest reboot per host that was not found to be a crash. pstore lines
	// that arrive after the crash check can still turn it into one.
	lastReboot map[string]*store.Incident
	// unlocked is called while Tick runs its queries, for tests.
	unlocked func()
}

func NewDetector(st *store.Store, rules *Rules, cfg Config, m *Metrics, log *slog.Logger) *Detector {
	if cfg.Context <= 0 {
		cfg.Context = 200
	}
	d := &Detector{Store: st, Log: log, Metrics: m, Wake: func() {}, cfg: cfg,
		hosts: map[string]*hostState{}, open: map[string]*store.Incident{}, dirty: map[int64]*store.Incident{},
		lastReboot: map[string]*store.Incident{}}
	d.SetRules(rules)
	return d
}

// SetRules replaces the rules, for example after a reload.
func (d *Detector) SetRules(r *Rules) { d.rules.Store(r) }

func openKey(host, boot, kind, rule string) string {
	return host + "|" + boot + "|" + kind + "|" + rule
}

func keyOf(i *store.Incident) string { return openKey(i.Host, i.BootID, i.Kind, i.Rule) }

// Load restores open incidents and known hosts. Hosts count as seen now, so a server
// restart does not make every host look silent.
func (d *Detector) Load(ctx context.Context, hosts []HostSeen, now time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	open, err := d.Store.OpenIncidents(ctx)
	if err != nil {
		return err
	}
	d.hmu.Lock()
	for _, h := range hosts {
		d.hosts[h.Host] = &hostState{boot: h.BootID, lastSeen: now}
	}
	for i := range open {
		inc := open[i]
		d.open[keyOf(&inc)] = &inc
		if h := d.hosts[inc.Host]; h != nil && inc.Kind == KindSilent {
			h.silent = true
		}
	}
	d.hmu.Unlock()
	recent, err := d.Store.Incidents(ctx, store.IncidentFilter{Limit: 1000})
	if err != nil {
		return err
	}
	done := map[string]bool{}
	for i := range recent {
		inc := recent[i]
		if done[inc.Host] || (inc.Kind != KindReboot && inc.Kind != KindCrash) {
			continue
		}
		done[inc.Host] = true
		if inc.Kind == KindReboot && !inc.Open() {
			d.lastReboot[inc.Host] = &inc
		}
	}
	d.updateOpen()
	return nil
}

// Seen notes a valid packet from host. It closes a silent incident when the host sends again.
func (d *Detector) Seen(host, boot string, now time.Time) {
	d.hmu.Lock()
	h := d.hosts[host]
	if h == nil {
		h = &hostState{}
		d.hosts[host] = h
	}
	h.boot, h.lastSeen = boot, now
	silent := h.silent
	d.hmu.Unlock()
	if !silent {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := openKey(host, boot, KindSilent, "")
	if inc := d.open[key]; inc != nil {
		inc.Summary += fmt.Sprintf(" (host sent again after %s)", now.Sub(inc.OpenedAt).Round(time.Second))
		inc.Resolved = true
		d.close(context.Background(), key, inc, now)
		d.Wake()
	}
	stillSilent := false
	for _, inc := range d.open {
		stillSilent = stillSilent || (inc.Host == host && inc.Kind == KindSilent)
	}
	d.hmu.Lock()
	h.silent = stillSilent
	d.hmu.Unlock()
}

// NewBoot is called once when a host starts a boot not seen before. prev is the boot before it, or "".
func (d *Detector) NewBoot(ctx context.Context, host, boot, prev string, now time.Time) {
	var last store.Record
	if prev != "" {
		last = d.lastRecord(ctx, host, prev)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hmu.Lock()
	d.hosts[host] = &hostState{boot: boot, lastSeen: now}
	d.hmu.Unlock()
	delete(d.lastReboot, host)
	if prev == "" {
		return
	}
	for key, inc := range d.open {
		if inc.Host == host && inc.BootID == prev && inc.Kind != KindReboot {
			d.close(ctx, key, inc, now)
		}
	}
	inc := &store.Incident{Host: host, BootID: prev, Kind: KindReboot, Severity: store.SeverityInfo,
		FirstRecordID: last.ID, LastRecordID: last.ID, Count: 1, OpenedAt: now, UpdatedAt: now,
		Summary: "Rebooted into boot " + short(boot) + "." + lastLine(last)}
	d.create(ctx, inc)
	d.updateOpen()
}

// Records checks newly stored kmsg records against the rules.
func (d *Detector) Records(ctx context.Context, recs []*store.Record, inserted []bool, now time.Time) {
	rules := d.rules.Load()
	d.mu.Lock()
	defer d.mu.Unlock()
	created := false
	late := map[*store.Incident]crashQuery{}
	for i, r := range recs {
		if !inserted[i] {
			continue
		}
		if r.Source == "pstore" {
			if lr := d.lastReboot[r.Host]; lr != nil && lr.BootID == r.BootID {
				late[lr] = crashQuery{lr.Host, lr.BootID, lr.LastRecordID}
			}
			continue
		}
		if r.Source != "kmsg" {
			continue
		}
		rule := rules.Match(r.Message)
		if rule == nil {
			continue
		}
		key := openKey(r.Host, r.BootID, KindKernelError, rule.Name)
		if inc := d.open[key]; inc != nil {
			inc.Count++
			inc.LastRecordID, inc.UpdatedAt = r.ID, now
			// Saved on the next tick, so a flood of errors does not cost one write each.
			d.dirty[inc.ID] = inc
			continue
		}
		d.create(ctx, &store.Incident{Host: r.Host, BootID: r.BootID, Kind: KindKernelError, Severity: rule.Severity,
			Rule: rule.Name, FirstRecordID: r.ID, LastRecordID: r.ID, Count: 1, Summary: r.Message, OpenedAt: now, UpdatedAt: now})
		created = true
	}
	found := map[*store.Incident]*crash{}
	if len(late) > 0 {
		d.mu.Unlock()
		for inc, q := range late {
			if c, err := d.checkCrash(ctx, q); err == nil && c != nil {
				found[inc] = c
			}
		}
		d.mu.Lock()
	}
	for inc, c := range found {
		// Another call may have decided while the lock was free.
		if d.lastReboot[inc.Host] != inc || inc.Kind != KindReboot {
			continue
		}
		d.markCrash(inc, c)
		delete(d.lastReboot, inc.Host)
		inc.UpdatedAt = now
		if err := d.Store.UpdateIncident(ctx, inc); err != nil {
			d.Log.Error("save incident", "err", err)
		}
		// A sent or skipped reboot alert does not cover a crash, so the alert starts over.
		if err := d.Store.ResetAlerts(ctx, inc.ID); err != nil {
			d.Log.Error("save incident", "err", err)
		}
		created = true
	}
	if created {
		d.updateOpen()
		d.Wake()
	}
}

// Tick finds silent hosts, decides pending reboots and saves changed incidents.
// It collects the work under the lock, runs the queries without it, then applies the results.
func (d *Detector) Tick(ctx context.Context, now time.Time) {
	type silentHost struct {
		host, boot string
		lastSeen   time.Time
		last       store.Record
	}
	type pendingReboot struct {
		key   string
		inc   *store.Incident
		q     crashQuery
		crash *crash
		err   error
	}
	var silent []silentHost
	var reboots []pendingReboot

	d.mu.Lock()
	wake := false
	d.hmu.Lock()
	for host, h := range d.hosts {
		if h.boot == "" || d.cfg.SilentAfter <= 0 || now.Sub(h.lastSeen) < d.cfg.SilentAfter {
			continue
		}
		if d.open[openKey(host, h.boot, KindSilent, "")] != nil {
			continue
		}
		silent = append(silent, silentHost{host: host, boot: h.boot, lastSeen: h.lastSeen})
	}
	d.hmu.Unlock()
	for key, inc := range d.open {
		switch {
		case inc.Kind == KindReboot && now.Sub(inc.OpenedAt) >= d.cfg.CrashWait:
			reboots = append(reboots, pendingReboot{key: key, inc: inc, q: crashQuery{inc.Host, inc.BootID, inc.LastRecordID}})
		case inc.Kind == KindKernelError && d.cfg.ResolveAfter > 0 && now.Sub(inc.UpdatedAt) >= d.cfg.ResolveAfter:
			inc.Summary += fmt.Sprintf(" (no new matching line for %s)", now.Sub(inc.UpdatedAt).Round(time.Second))
			inc.Resolved = true
			d.close(ctx, key, inc, now)
			wake = true
		}
	}
	d.mu.Unlock()

	for i := range silent {
		silent[i].last = d.lastRecord(ctx, silent[i].host, silent[i].boot)
	}
	for i := range reboots {
		// Without the logs a crash would look like a clean reboot, so the check waits for the database.
		reboots[i].crash, reboots[i].err = d.checkCrash(ctx, reboots[i].q)
	}
	if d.unlocked != nil {
		d.unlocked()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range silent {
		// The host may have sent again while the lock was free.
		d.hmu.Lock()
		h := d.hosts[s.host]
		still := h != nil && h.boot == s.boot && h.lastSeen.Equal(s.lastSeen)
		if still {
			h.silent = true
		}
		d.hmu.Unlock()
		if !still || d.open[openKey(s.host, s.boot, KindSilent, "")] != nil {
			continue
		}
		d.create(ctx, &store.Incident{Host: s.host, BootID: s.boot, Kind: KindSilent, Severity: store.SeverityWarning,
			FirstRecordID: s.last.ID, LastRecordID: s.last.ID, Count: 1, OpenedAt: now, UpdatedAt: now,
			Summary: fmt.Sprintf("No packets for %s.", now.Sub(s.lastSeen).Round(time.Second)) + lastLine(s.last)})
		wake = true
	}
	for _, r := range reboots {
		if r.err != nil || d.open[r.key] != r.inc {
			continue
		}
		inc := r.inc
		if r.crash != nil {
			d.markCrash(inc, r.crash)
		}
		d.close(ctx, r.key, inc, now)
		if inc.Kind == KindReboot {
			d.lastReboot[inc.Host] = inc
			// A clean reboot ends the problems of the old boot.
			for _, k := range []string{KindKernelError, KindSilent} {
				if err := d.Store.ResolveKind(ctx, inc.Host, inc.BootID, k); err != nil {
					d.Log.Error("save incident", "err", err)
				}
			}
		}
		wake = true
	}
	d.saveDirty(ctx)
	d.updateOpen()
	if wake {
		d.Wake()
	}
}

func (d *Detector) saveDirty(ctx context.Context) {
	for id, inc := range d.dirty {
		if err := d.Store.UpdateIncident(ctx, inc); err != nil {
			d.Log.Error("save incident", "err", err)
			continue
		}
		delete(d.dirty, id)
	}
}

// Flush saves incident changes not written yet, like counts of grouped kernel errors.
func (d *Detector) Flush(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.saveDirty(ctx)
}

// Forget drops hosts not seen since cutoff, so hosts removed by retention do not turn silent again.
func (d *Detector) Forget(cutoff time.Time) {
	d.hmu.Lock()
	defer d.hmu.Unlock()
	for host, h := range d.hosts {
		if h.lastSeen.Before(cutoff) {
			delete(d.hosts, host)
		}
	}
}

// Run calls Tick every second until ctx is done.
func (d *Detector) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.Flush(context.WithoutCancel(ctx))
			return
		case now := <-t.C:
			d.Tick(ctx, now)
		}
	}
}

// crashQuery names the old boot of a reboot incident, copied so the check can run without the lock.
type crashQuery struct {
	host, boot   string
	lastRecordID int64
}

// crash is what the crash check found.
type crash struct {
	rule, summary string
	count         int
}

// checkCrash finds whether the old boot left pstore lines or ended with a critical kernel line.
// It returns nil for a clean reboot. It only reads the database and runs without the lock.
func (d *Detector) checkCrash(ctx context.Context, q crashQuery) (*crash, error) {
	rules := d.rules.Load()
	pstore, err := d.Store.Query(ctx, store.Filter{Host: q.host, BootID: q.boot, Source: "pstore", MaxLevel: -1, Oldest: true, Limit: 10000})
	if err != nil {
		d.Log.Error("crash check, will retry", "err", err)
		return nil, err
	}
	var tail []store.Record
	if q.lastRecordID > 0 {
		tail, err = d.Store.Query(ctx, store.Filter{Host: q.host, BootID: q.boot, Source: "kmsg", MaxLevel: -1,
			BeforeID: q.lastRecordID + 1, Limit: d.cfg.Context})
		if err != nil {
			d.Log.Error("crash check, will retry", "err", err)
			return nil, err
		}
	}
	var hit *Rule
	var line string
	for i := range pstore {
		if r := rules.Match(pstore[i].Message); r != nil && r.Severity == store.SeverityCritical {
			hit, line = r, pstore[i].Message
			break
		}
	}
	// The tail is newest first; the oldest critical line is usually the cause.
	for i := len(tail) - 1; i >= 0 && hit == nil; i-- {
		if r := rules.Match(tail[i].Message); r != nil && r.Severity == store.SeverityCritical {
			hit, line = r, tail[i].Message
		}
	}
	if hit == nil && len(pstore) == 0 {
		return nil, nil
	}
	c := &crash{count: len(pstore)}
	switch {
	case hit != nil:
		c.rule, c.summary = hit.Name, line
	default:
		c.rule = "pstore"
		c.summary = fmt.Sprintf("The kernel saved %d lines before the reboot. Last: %s", len(pstore), pstore[len(pstore)-1].Message)
	}
	return c, nil
}

// markCrash turns a reboot incident into a crash. It is called with the lock held.
func (d *Detector) markCrash(inc *store.Incident, c *crash) {
	inc.Kind, inc.Severity, inc.Count = KindCrash, store.SeverityCritical, c.count
	inc.Rule, inc.Summary = c.rule, c.summary
	d.Metrics.Created.WithLabelValues(inc.Host, KindCrash).Inc()
	d.Log.Info("incident is a crash", "id", inc.ID, "host", inc.Host, "rule", inc.Rule, "summary", inc.Summary)
}

func (d *Detector) create(ctx context.Context, inc *store.Incident) {
	if err := d.Store.CreateIncident(ctx, inc); err != nil {
		d.Log.Error("save incident", "err", err)
		return
	}
	d.open[keyOf(inc)] = inc
	d.Metrics.Created.WithLabelValues(inc.Host, inc.Kind).Inc()
	d.Log.Info("incident", "id", inc.ID, "host", inc.Host, "kind", inc.Kind, "severity", inc.Severity.String(), "summary", inc.Summary)
}

func (d *Detector) close(ctx context.Context, key string, inc *store.Incident, now time.Time) {
	inc.ClosedAt, inc.UpdatedAt = now, now
	delete(d.open, key)
	delete(d.dirty, inc.ID)
	if err := d.Store.UpdateIncident(ctx, inc); err != nil {
		d.Log.Error("save incident", "err", err)
	}
}

func (d *Detector) lastRecord(ctx context.Context, host, boot string) store.Record {
	recs, err := d.Store.Query(ctx, store.Filter{Host: host, BootID: boot, MaxLevel: -1, Limit: 1})
	if err != nil {
		d.Log.Error("incident context", "err", err)
	}
	if len(recs) == 0 {
		return store.Record{}
	}
	return recs[0]
}

func (d *Detector) updateOpen() {
	n := map[string]int{}
	for _, inc := range d.open {
		n[inc.Kind]++
	}
	for _, k := range kinds {
		d.Metrics.Open.WithLabelValues(k).Set(float64(n[k]))
	}
}

func lastLine(r store.Record) string {
	if r.ID == 0 {
		return ""
	}
	return " Last line: " + r.Message
}

func short(boot string) string {
	if len(boot) > 8 {
		return boot[:8]
	}
	return boot
}
