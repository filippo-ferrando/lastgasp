package server

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the server side Prometheus metrics.
type Metrics struct {
	Invalid      *prometheus.CounterVec
	Stored       *prometheus.CounterVec
	Deduplicated *prometheus.CounterVec
	QueueDropped prometheus.Counter
	Probes       prometheus.Counter
	StoreErrors  prometheus.Counter
	LostToStore  prometheus.Counter
	KeyReloads   *prometheus.CounterVec
	AuthFailures prometheus.Counter
	AuthBlocked  prometheus.Counter
	// RetentionDeleted counts rows removed by retention, per table.
	RetentionDeleted *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer, tr *Tracker, staleAfter time.Duration) *Metrics {
	m := &Metrics{
		Invalid: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lastgasp_packets_invalid_total", Help: "Packets rejected before processing.",
		}, []string{"reason"}),
		Stored: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lastgasp_records_stored_total", Help: "Log records saved.",
		}, []string{"host", "source"}),
		Deduplicated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lastgasp_records_deduplicated_total", Help: "Log records skipped because they were already saved.",
		}, []string{"host", "source"}),
		QueueDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lastgasp_server_queue_dropped_total", Help: "Valid packets dropped because the server could not keep up.",
		}),
		Probes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lastgasp_probes_total", Help: "Probes from agents waiting for a server to answer.",
		}),
		StoreErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lastgasp_store_errors_total", Help: "Database errors.",
		}),
		LostToStore: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lastgasp_records_lost_total", Help: "Records lost because the database failed after retries.",
		}),
		KeyReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lastgasp_key_reloads_total", Help: "Key file reloads by result (ok, error).",
		}, []string{"result"}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lastgasp_auth_failures_total", Help: "HTTP requests with a wrong user, password or token.",
		}),
		AuthBlocked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lastgasp_auth_blocked_total", Help: "HTTP requests refused because of too many failed logins.",
		}),
		RetentionDeleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lastgasp_retention_deleted_total", Help: "Rows deleted because they are older than the retention period.",
		}, []string{"table"}),
	}
	reg.MustRegister(m.Invalid, m.Stored, m.Deduplicated, m.QueueDropped, m.Probes, m.StoreErrors, m.LostToStore, m.KeyReloads, m.AuthFailures, m.AuthBlocked, m.RetentionDeleted,
		&trackerCollector{tr: tr, staleAfter: staleAfter})
	return m
}

// ForgetHost removes the per host label values of a host that retention removed.
func (m *Metrics) ForgetHost(host string) {
	m.Stored.DeletePartialMatch(prometheus.Labels{"host": host})
	m.Deduplicated.DeletePartialMatch(prometheus.Labels{"host": host})
}

// trackerCollector reads per host packet counters from the tracker at scrape time.
type trackerCollector struct {
	tr         *Tracker
	staleAfter time.Duration
}

func desc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, []string{"host"}, nil)
}

var (
	descReceived   = desc("lastgasp_packets_received_total", "Unique packets received.")
	descGaps       = desc("lastgasp_packets_gap_total", "Packets found missing from the sequence.")
	descRecovered  = desc("lastgasp_packets_late_total", "Missing packets that arrived later, out of order.")
	descMissing    = desc("lastgasp_packets_missing", "Packets still missing.")
	descDuplicates = desc("lastgasp_packets_duplicate_total", "Packets received more than once.")
	descLastSeen   = desc("lastgasp_agent_last_seen_timestamp_seconds", "Time of the last packet from the agent.")
	descUp         = desc("lastgasp_agent_up", "1 if the agent sent a packet recently.")
	descDrops      = desc("lastgasp_agent_buffer_dropped_total", "Records dropped by the agent because its buffer was full.")
	descOverruns   = desc("lastgasp_agent_kmsg_overruns_total", "Times the kernel overwrote records before the agent read them.")
	descSendErrors = desc("lastgasp_agent_send_errors_total", "Failed sends reported by the agent.")
	descBuffered   = desc("lastgasp_agent_buffered_records", "Records waiting in the agent buffer.")
)

func (c *trackerCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descReceived, descGaps, descRecovered, descMissing, descDuplicates,
		descLastSeen, descUp, descDrops, descOverruns, descSendErrors, descBuffered} {
		ch <- d
	}
}

func (c *trackerCollector) Collect(ch chan<- prometheus.Metric) {
	counter, gauge := prometheus.CounterValue, prometheus.GaugeValue
	for _, h := range c.tr.Hosts(time.Now(), c.staleAfter) {
		up := 0.0
		if h.Up {
			up = 1
		}
		for _, m := range []struct {
			d *prometheus.Desc
			t prometheus.ValueType
			v float64
		}{
			{descReceived, counter, float64(h.Received)},
			{descGaps, counter, float64(h.Gaps)},
			{descRecovered, counter, float64(h.Recovered)},
			{descMissing, gauge, float64(h.Missing)},
			{descDuplicates, counter, float64(h.Duplicates)},
			{descLastSeen, gauge, float64(h.LastSeen.UnixMilli()) / 1000},
			{descUp, gauge, up},
			{descDrops, counter, float64(h.Agent.BufferDrops)},
			{descOverruns, counter, float64(h.Agent.KmsgOverruns)},
			{descSendErrors, counter, float64(h.Agent.SendErrors)},
			{descBuffered, gauge, float64(h.Agent.Buffered)},
		} {
			// Never panic in a scrape: a bad label value only skips that metric.
			if pm, err := prometheus.NewConstMetric(m.d, m.t, m.v, h.Host); err == nil {
				ch <- pm
			}
		}
	}
}
