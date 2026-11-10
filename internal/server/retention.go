package server

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"lastgasp/internal/incident"
	"lastgasp/internal/store"
)

// Retention deletes old data. Every limit is optional, zero turns it off.
type Retention struct {
	Store    *store.Store
	Tracker  *Tracker
	Detector *incident.Detector // may be nil
	Metrics  *Metrics
	Log      *slog.Logger
	// Age removes records, closed incidents, old boots and agent runs older than this.
	Age time.Duration
	// InfoAge removes records of level info and debug older than this.
	InfoAge time.Duration
	// MaxRecords and MaxHostRecords keep the newest records, in total and per host.
	MaxRecords     int
	MaxHostRecords int
	// MaxBytes keeps the records under this size, as estimated by Store.RecordsSize.
	MaxBytes int64
	Every    time.Duration
}

// Enabled reports whether any limit is set.
func (r *Retention) Enabled() bool {
	return r.Age > 0 || r.InfoAge > 0 || r.MaxRecords > 0 || r.MaxHostRecords > 0 || r.MaxBytes > 0
}

// Run deletes old data a minute after start and then every r.Every, until ctx is done.
func (r *Retention) Run(ctx context.Context) {
	wait := time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := r.RunOnce(ctx, time.Now()); err != nil && ctx.Err() == nil {
			r.Log.Error("retention", "err", err)
			r.Metrics.StoreErrors.Inc()
		}
		wait = r.Every
	}
}

// RunOnce applies every limit as of now.
func (r *Retention) RunOnce(ctx context.Context, now time.Time) error {
	recs, err := r.trim(ctx, now)
	if recs > 0 {
		r.Log.Info("retention", "records", recs)
	}
	if err != nil || r.Age <= 0 {
		return err
	}
	return r.byAge(ctx, now)
}

// trim applies the limits that only remove records.
func (r *Retention) trim(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	count := func(n int64, err error) error {
		total += n
		r.Metrics.RetentionDeleted.WithLabelValues("records").Add(float64(n))
		return err
	}
	// Info and debug lines are the bulk of most logs, so they go first.
	if r.InfoAge > 0 {
		if err := count(r.Store.DeleteLevelBefore(ctx, 6, now.Add(-r.InfoAge))); err != nil {
			return total, err
		}
	}
	if r.MaxHostRecords > 0 {
		hosts, err := r.Store.RecordHosts(ctx)
		if err != nil {
			return total, err
		}
		for _, h := range hosts {
			if err := count(r.Store.TrimRecords(ctx, h, r.MaxHostRecords)); err != nil {
				return total, err
			}
		}
	}
	if r.MaxRecords > 0 {
		if err := count(r.Store.TrimRecords(ctx, "", r.MaxRecords)); err != nil {
			return total, err
		}
	}
	// The size also holds other tables, so one cut may not be enough: measure again after each one.
	for range 5 {
		if r.MaxBytes <= 0 {
			break
		}
		size, rows, err := r.Store.RecordsSize(ctx)
		if err != nil || size <= r.MaxBytes {
			return total, err
		}
		// Trim to 90% of the limit, so the next run does not trim again right away.
		keep := int(float64(rows) * 0.9 * float64(r.MaxBytes) / float64(size))
		n, err := r.Store.TrimRecords(ctx, "", keep)
		if err := count(n, err); err != nil || n == 0 {
			return total, err
		}
	}
	return total, nil
}

// ParseSize reads a byte count such as "500000", "512MiB" or "20G". Suffixes are powers of 1024.
func ParseSize(v string) (int64, error) {
	num := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(v), "B"), "i")
	shift := 0
	for i, u := range "KMGT" {
		if cut, ok := strings.CutSuffix(num, string(u)); ok {
			shift, num = 10*(i+1), cut
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 || n > math.MaxInt64>>shift {
		return 0, fmt.Errorf("invalid size %q", v)
	}
	return n << shift, nil
}

// byAge deletes everything older than now minus r.Age.
func (r *Retention) byAge(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-r.Age)
	recs, err := r.Store.DeleteRecordsBefore(ctx, cutoff)
	r.Metrics.RetentionDeleted.WithLabelValues("records").Add(float64(recs))
	if err != nil {
		return err
	}
	n, err := r.Store.DeleteIncidentsBefore(ctx, cutoff)
	if err != nil {
		return err
	}
	r.Metrics.RetentionDeleted.WithLabelValues("incidents").Add(float64(n))
	if n, err = r.Store.DeleteBootsBefore(ctx, cutoff); err != nil {
		return err
	}
	r.Metrics.RetentionDeleted.WithLabelValues("boots").Add(float64(n))
	if n, err = r.Store.DeleteSilencesBefore(ctx, cutoff); err != nil {
		return err
	}
	r.Metrics.RetentionDeleted.WithLabelValues("silences").Add(float64(n))
	streams := r.Tracker.Prune(cutoff)
	for i, s := range streams {
		if err := r.Store.DeleteStream(ctx, s.Host, s.BootID, s.Instance); err != nil {
			// Put the rest back, so they are deleted on the next run.
			r.Tracker.Restore(streams[i:])
			return err
		}
	}
	r.Metrics.RetentionDeleted.WithLabelValues("streams").Add(float64(len(streams)))
	live := map[string]bool{}
	for _, s := range r.Tracker.Snapshot() {
		live[s.Host] = true
	}
	for _, s := range streams {
		if !live[s.Host] {
			r.Metrics.ForgetHost(s.Host)
		}
	}
	if r.Detector != nil {
		r.Detector.Forget(cutoff)
	}
	if recs > 0 || len(streams) > 0 {
		r.Log.Info("retention", "cutoff", cutoff.UTC().Format(time.RFC3339), "records", recs, "streams", len(streams))
	}
	return nil
}
