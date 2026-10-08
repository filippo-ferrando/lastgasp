package server

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"lastgasp/internal/incident"
	"lastgasp/internal/store"
)

// Check is one server counter that should not grow. Min is the growth in one run that opens an
// incident, 0 means any growth.
type Check struct {
	Rule     string
	Severity store.Severity
	Summary  string
	Value    func() float64
	Min      int
}

// SelfCheck opens server incidents when a checked counter grows, so problems of the server
// reach the alert targets without a Prometheus setup.
type SelfCheck struct {
	Detector *incident.Detector
	Checks   []Check
	Every    time.Duration

	last map[string]float64
}

// ServerChecks watches database errors, lost records, dropped packets, failed alerts, packets with a bad key
// and replayed packets.
func ServerChecks(m *Metrics, im *incident.Metrics) []Check {
	return []Check{
		{"records_lost", store.SeverityCritical, "Records lost because the database kept failing. Check the database and the server log.",
			func() float64 { return sum(m.LostToStore, nil) }, 0},
		{"database", store.SeverityWarning, "Database errors. Check the database and the server log.",
			func() float64 { return sum(m.StoreErrors, nil) }, 0},
		{"queue", store.SeverityWarning, "Packets dropped because the server could not keep up. Raise -rcvbuf or check the database speed.",
			func() float64 { return sum(m.QueueDropped, nil) }, 0},
		{"alerts", store.SeverityWarning, "Alerts could not be sent. Check the alert targets and the server log.",
			func() float64 { return sum(im.Alerts, map[string]string{"result": "failed"}) }, 0},
		{"keys", store.SeverityWarning, "Packets with an unknown host or a wrong key. Check the key file and the agent keys.",
			func() float64 {
				return sum(m.Invalid, map[string]string{"reason": "unknown_host"}) + sum(m.Invalid, map[string]string{"reason": "auth_failed"})
			}, 0},
		// A network can deliver a packet twice now and then, many in a short time mean someone sends recorded traffic.
		{"replay", store.SeverityWarning, "Version 5 packets or handshakes received more than once. Many of them mean someone sends recorded traffic again.",
			func() float64 { return sum(m.Invalid, map[string]string{"reason": "replay"}) }, replayMin},
	}
}

// replayMin is the number of replays within one self check run that opens an incident.
const replayMin = 20

// sum adds the values of every metric of c whose labels include want.
func sum(c prometheus.Collector, want map[string]string) float64 {
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	total := 0.0
	for m := range ch {
		var pb dto.Metric
		if m.Write(&pb) != nil {
			continue
		}
		match := 0
		for _, l := range pb.GetLabel() {
			if v, ok := want[l.GetName()]; ok && v == l.GetValue() {
				match++
			}
		}
		if match == len(want) {
			total += pb.GetCounter().GetValue() + pb.GetGauge().GetValue()
		}
	}
	return total
}

// Run checks every s.Every until ctx is done.
func (s *SelfCheck) Run(ctx context.Context) {
	t := time.NewTicker(s.Every)
	defer t.Stop()
	s.RunOnce(ctx, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.RunOnce(ctx, now)
		}
	}
}

// RunOnce compares each counter with the last run. Counters start at zero with the server.
func (s *SelfCheck) RunOnce(ctx context.Context, now time.Time) {
	if s.last == nil {
		s.last = map[string]float64{}
	}
	for _, c := range s.Checks {
		v := c.Value()
		n := int(v - s.last[c.Rule])
		s.last[c.Rule] = v
		if n > 0 && n >= c.Min {
			s.Detector.ServerProblem(ctx, c.Rule, c.Severity, n, c.Summary, now)
		}
	}
}
