package incident

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

// MaxAlertAge limits alerts to incidents updated recently, so a new target is not flooded with old ones.
const MaxAlertAge = 24 * time.Hour

// Notifier sends incidents to one target, a webhook or an email. An incident is marked sent only after
// the target took it, so alerts not sent before a restart are sent after it.
type Notifier struct {
	Store       *store.Store
	Name        string // target name, the key of its alert state
	Email       *Email // set for an email target, URL is used otherwise
	URL         string
	Format      string // "json" or "slack"
	Key         []byte // signs the body when set
	PublicURL   string // base URL of the web UI, for links
	MinSeverity store.Severity
	RateLimit   time.Duration // per host and kind
	Client      *http.Client
	Metrics     *Metrics
	Log         *slog.Logger

	once sync.Once
	wake chan struct{}
	last map[string]time.Time
	now  func() time.Time
}

// Payload is the JSON body sent with the "json" format.
type Payload struct {
	Text     string         `json:"text"`
	URL      string         `json:"url,omitempty"`
	Resolved bool           `json:"resolved"` // the incident is over, sent after an earlier alert
	Target   string         `json:"target"`
	Incident store.Incident `json:"incident"`
}

// init runs once, because Wake and Run can be called from different goroutines.
func (n *Notifier) init() {
	n.once.Do(func() {
		n.wake = make(chan struct{}, 1)
		n.last = map[string]time.Time{}
		if n.now == nil {
			n.now = time.Now
		}
		if n.Client == nil {
			n.Client = &http.Client{Timeout: 10 * time.Second}
		}
	})
}

// Wake asks for pending alerts to be sent now. It never blocks.
func (n *Notifier) Wake() {
	n.init()
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// Run sends pending alerts until ctx is done. It also checks every 10 seconds.
func (n *Notifier) Run(ctx context.Context) {
	n.init()
	retry := time.Second
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		wait := retry
		if err := n.flush(ctx); err != nil {
			n.Log.Warn("alert", "target", n.Name, "err", err, "retry_in", retry)
			retry = min(retry*2, 5*time.Minute)
		} else {
			retry, wait = time.Second, 0
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-n.wake:
		case <-t.C:
		}
	}
}

// flush sends all pending alerts and stops at the first failure.
func (n *Notifier) flush(ctx context.Context) error {
	for {
		pending, err := n.Store.PendingAlerts(ctx, n.Name, n.MinSeverity, n.now().Add(-MaxAlertAge), 50)
		if err != nil || len(pending) == 0 {
			return err
		}
		for i := range pending {
			p := &pending[i]
			key := p.Host + "|" + p.Kind
			state := store.AlertSent
			switch {
			case p.Resolve:
				state = store.AlertResolved
			case p.Kind == KindSilent && p.Resolved:
				// A short blip: the host came back before this target heard about it.
				state = store.AlertSkipped
			case n.RateLimit > 0 && n.now().Sub(n.last[key]) < n.RateLimit:
				state = store.AlertSuppressed
			}
			if state == store.AlertSent || state == store.AlertResolved {
				if err := n.send(ctx, p); err != nil {
					n.Metrics.Alerts.WithLabelValues(n.Name, "failed").Inc()
					return err
				}
				if !p.Resolve {
					n.last[key] = n.now()
				}
			}
			n.Metrics.Alerts.WithLabelValues(n.Name, state).Inc()
			if err := n.Store.SetAlert(ctx, p.ID, n.Name, state, n.now()); err != nil {
				return err
			}
		}
	}
}

func (n *Notifier) link(id int64) string {
	if n.PublicURL == "" {
		return ""
	}
	return strings.TrimRight(n.PublicURL, "/") + "/#incident=" + strconv.FormatInt(id, 10)
}

func (n *Notifier) send(ctx context.Context, p *store.PendingAlert) error {
	if n.Email != nil {
		return n.sendEmail(ctx, p)
	}
	inc := &p.Incident
	link := n.link(inc.ID)
	text := Text(inc, p.Resolve, link)
	var body []byte
	if n.Format == "slack" {
		body, _ = json.Marshal(map[string]string{"text": text})
	} else {
		body, _ = json.Marshal(Payload{Text: text, URL: link, Resolved: p.Resolve, Target: n.Name, Incident: *inc})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "lastgasp-server")
	if len(n.Key) > 0 {
		req.Header.Set("X-Lastgasp-Signature", "sha256="+Sign(n.Key, body))
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook %s answered %s", n.Name, resp.Status)
	}
	return nil
}

// Sign returns the hex HMAC-SHA256 of body, sent in the X-Lastgasp-Signature header.
func Sign(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Headline is a short description of an incident, like "[critical] db-01 crashed".
func Headline(inc *store.Incident, resolved bool) string {
	what := map[string]string{KindCrash: "crashed", KindReboot: "rebooted", KindSilent: "went silent",
		KindKernelError: "kernel error (" + inc.Rule + ")"}[inc.Kind]
	if what == "" {
		what = inc.Kind
	}
	level := inc.Severity.String()
	if resolved {
		level = "resolved"
		switch inc.Kind {
		case KindSilent:
			what = "is sending again"
		case KindKernelError:
			what = "kernel error (" + inc.Rule + ") is over"
		}
	}
	return fmt.Sprintf("[%s] %s %s", level, inc.Host, what)
}

// Text is a one line description of an incident for chat messages.
func Text(inc *store.Incident, resolved bool, link string) string {
	s := Headline(inc, resolved) + ": " + inc.Summary
	if len(s) > 1000 {
		s = strings.ToValidUTF8(s[:1000], "") + "..."
	}
	if link != "" {
		s += " " + link
	}
	return s
}

// ParseTarget reads an -alert-webhook value: a plain URL, or "name=N,format=F,min=S,key-file=P,rate=D,url=U".
// url must come last, so the URL may hold commas. Options not given are taken from def.
// The default name is the URL host, so secrets in the URL never show up in metrics or the UI.
func ParseTarget(spec string, def *Notifier) (*Notifier, error) {
	n := &Notifier{Store: def.Store, Format: def.Format, Key: def.Key, PublicURL: def.PublicURL, MinSeverity: def.MinSeverity,
		RateLimit: def.RateLimit, Client: def.Client, Metrics: def.Metrics, Log: def.Log}
	rest := spec
	if !strings.HasPrefix(spec, "http://") && !strings.HasPrefix(spec, "https://") {
		for rest != "" {
			if u, ok := strings.CutPrefix(rest, "url="); ok {
				rest = u
				break
			}
			opt, after, _ := strings.Cut(rest, ",")
			rest = after
			k, v, _ := strings.Cut(opt, "=")
			switch k {
			case "name":
				n.Name = v
			case "format":
				n.Format = v
			case "min":
				sev, err := store.ParseSeverity(v)
				if err != nil {
					return nil, err
				}
				n.MinSeverity = sev
			case "key-file":
				b, err := os.ReadFile(v)
				if err != nil {
					return nil, err
				}
				if n.Key, err = wire.ParseKey(string(b)); err != nil {
					return nil, fmt.Errorf("%s: %w", v, err)
				}
			case "rate":
				d, err := time.ParseDuration(v)
				if err != nil {
					return nil, err
				}
				n.RateLimit = d
			default:
				return nil, fmt.Errorf("unknown webhook option %q", k)
			}
		}
	}
	u, err := url.Parse(rest)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("webhook %q: want an http or https URL, given last as url=...", spec)
	}
	n.URL = rest
	if n.Name == "" {
		n.Name = u.Hostname()
	}
	if n.Format != "json" && n.Format != "slack" {
		return nil, fmt.Errorf("webhook %s: format must be json or slack", n.Name)
	}
	return n, nil
}

// Notifiers sends to several targets. Each target has its own state, backoff and rate limit.
type Notifiers []*Notifier

// Wake asks every target to send pending alerts now.
func (ns Notifiers) Wake() {
	for _, n := range ns {
		n.Wake()
	}
}

// Run runs every target until ctx is done.
func (ns Notifiers) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, n := range ns {
		wg.Add(1)
		go func() { defer wg.Done(); n.Run(ctx) }()
	}
	wg.Wait()
}
