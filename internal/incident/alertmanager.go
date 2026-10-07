package incident

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"lastgasp/internal/store"
)

// Alertmanager forgets an alert at its endsAt, so open incidents are sent again every amRefresh
// with an end amHold ahead. One-time events like a crash end amEvent after they are sent.
const (
	amRefresh = time.Minute
	amHold    = 5 * time.Minute
	amEvent   = time.Hour
)

// amAlert is one alert of the Alertmanager v2 API (POST /api/v2/alerts).
type amAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// amName turns a kind into an alert name, like kernel_error into LastgaspKernelError.
func amName(kind string) string {
	name := "Lastgasp"
	for _, w := range strings.Split(kind, "_") {
		if w != "" {
			name += strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return name
}

func (n *Notifier) amAlert(inc *store.Incident, resolved bool) amAlert {
	a := amAlert{
		Labels: map[string]string{"alertname": amName(inc.Kind), "host": inc.Host, "kind": inc.Kind,
			"severity": inc.Severity.String(), "incident": strconv.FormatInt(inc.ID, 10)},
		Annotations:  map[string]string{"summary": Headline(inc, false), "description": inc.Summary},
		StartsAt:     inc.OpenedAt,
		GeneratorURL: n.link(inc.ID),
	}
	if inc.Rule != "" {
		a.Labels["rule"] = inc.Rule
	}
	if a.GeneratorURL != "" {
		a.Annotations["url"] = a.GeneratorURL
	}
	now := n.now()
	switch {
	case resolved:
		a.EndsAt = inc.ClosedAt
		if a.EndsAt.IsZero() || a.EndsAt.After(now) {
			a.EndsAt = now
		}
	case inc.Open():
		a.EndsAt = now.Add(amHold)
	default:
		a.EndsAt = now.Add(amEvent)
	}
	return a
}

// refresh sends the open incidents this target alerted on again, so Alertmanager keeps them firing.
func (n *Notifier) refresh(ctx context.Context) error {
	incs, err := n.Store.SentOpenIncidents(ctx, n.Name)
	if err != nil || len(incs) == 0 {
		return err
	}
	alerts := make([]amAlert, len(incs))
	for i := range incs {
		alerts[i] = n.amAlert(&incs[i], false)
	}
	body, _ := json.Marshal(alerts)
	return n.post(ctx, n.URL, body)
}
