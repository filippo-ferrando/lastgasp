package incident

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lastgasp/internal/store"
)

func TestTelegramTarget(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var mu sync.Mutex
	var paths, bodies []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		paths, bodies = append(paths, r.URL.Path), append(bodies, string(b))
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tokenFile, []byte("123:secret-token\n"), 0o600)
	def := &Notifier{Store: e.st, PublicURL: "https://lg.example", MinSeverity: store.SeverityWarning, Metrics: e.d.Metrics, Log: e.d.Log}
	n, err := ParseTelegramTarget("chat=-1001,token-file="+tokenFile+",api="+api.URL, def)
	if err != nil || n.Name != "telegram" {
		t.Fatalf("parse: %+v %v", n, err)
	}
	n.init()
	e.add(t, "h", "b1", "kmsg", e.t0, "Kernel panic - not syncing: x")
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/bot123:secret-token/sendMessage" {
		t.Fatalf("paths %v", paths)
	}
	var msg struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
	}
	json.Unmarshal([]byte(bodies[0]), &msg)
	if msg.ChatID != "-1001" || msg.Text != "[critical] h kernel error (panic)\nKernel panic - not syncing: x\nhttps://lg.example/#incident=1" {
		t.Fatalf("message %+v", msg)
	}

	// A failed request must not put the token in the log or the error.
	n.Telegram.API = "http://127.0.0.1:1"
	err = n.send(ctx, &store.PendingAlert{Incident: store.Incident{Host: "h", Kind: KindCrash}})
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error %v", err)
	}

	for _, bad := range []string{"chat=1", "token-file=" + tokenFile, "chat=1,token-file=/missing", "chat=1,token-file=" + tokenFile + ",api=ftp://x",
		"chat=1,token-file=" + tokenFile + ",loud=1", "chat"} {
		if _, err := ParseTelegramTarget(bad, def); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	os.WriteFile(tokenFile, []byte("123:abc/../x"), 0o600)
	if _, err := ParseTelegramTarget("chat=1,token-file="+tokenFile, def); err == nil {
		t.Error("token with a slash accepted")
	}
}

func TestAlertmanagerFormat(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &hook{}
	def := &Notifier{Store: e.st, Format: "json", PublicURL: "https://lg.example", MinSeverity: store.SeverityWarning,
		Metrics: e.d.Metrics, Log: e.d.Log}
	n, err := ParseTarget("name=am,format=alertmanager,url="+newHook(t, h)+"/api/v2/alerts", def)
	if err != nil {
		t.Fatal(err)
	}
	n.init()
	now := e.t0.Add(time.Minute)
	n.now = func() time.Time { return now }
	e.add(t, "db-01", "b1", "kmsg", e.t0, "Out of memory: Killed process 1")
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	var alerts []amAlert
	if err := json.Unmarshal([]byte(h.bodies[0]), &alerts); err != nil || len(alerts) != 1 {
		t.Fatalf("body %s: %v", h.bodies[0], err)
	}
	a := alerts[0]
	if a.Labels["alertname"] != "LastgaspKernelError" || a.Labels["host"] != "db-01" || a.Labels["rule"] != "oom" ||
		a.Labels["severity"] != "warning" || a.Labels["incident"] != "1" || a.GeneratorURL != "https://lg.example/#incident=1" ||
		a.Annotations["description"] != "Out of memory: Killed process 1" || !a.StartsAt.Equal(e.t0) || !a.EndsAt.Equal(now.Add(amHold)) {
		t.Fatalf("alert %+v", a)
	}

	// While open, the incident is sent again so Alertmanager keeps it firing.
	now = now.Add(2 * time.Minute)
	if err := n.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(h.bodies[1]), &alerts)
	if len(alerts) != 1 || !alerts[0].EndsAt.Equal(now.Add(amHold)) {
		t.Fatalf("refresh %s", h.bodies[1])
	}

	// Resolved: the end is the close time, and the incident is no longer refreshed.
	e.d.cfg.ResolveAfter = time.Minute
	e.d.Seen("db-01", "b1", now)
	e.d.Tick(ctx, now)
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(h.bodies[2]), &alerts)
	if len(alerts) != 1 || !alerts[0].EndsAt.Equal(now) {
		t.Fatalf("resolve %s", h.bodies[2])
	}
	if err := n.refresh(ctx); err != nil || len(h.bodies) != 3 {
		t.Fatalf("refreshed a closed incident: %v %d", err, len(h.bodies))
	}
	if amName(KindServer) != "LastgaspServer" || amName(KindCrash) != "LastgaspCrash" {
		t.Fatal("alert names")
	}
}
