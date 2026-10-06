package server

import (
	"context"
	"log/slog"
	"time"

	"lastgasp/internal/incident"
	"lastgasp/internal/store"
)

// Retention deletes data older than Age: records, closed incidents, old boots and agent runs.
type Retention struct {
	Store    *store.Store
	Tracker  *Tracker
	Detector *incident.Detector // may be nil
	Metrics  *Metrics
	Log      *slog.Logger
	Age      time.Duration
	Every    time.Duration
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

// RunOnce deletes everything older than now minus r.Age.
func (r *Retention) RunOnce(ctx context.Context, now time.Time) error {
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
