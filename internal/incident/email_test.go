package incident

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/pem"
	"net"
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

// fakeSMTP is a tiny SMTP server that keeps every mail it gets.
type fakeSMTP struct {
	ln    net.Listener
	mu    sync.Mutex
	mails []string
	auth  string // decoded AUTH PLAIN of the last session
	rcpt  []string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return
		}
		l = strings.TrimRight(l, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(l, " ", 2)[0])
		switch cmd {
		case "EHLO", "HELO":
			say("250-fake")
			say("250 AUTH PLAIN")
		case "AUTH":
			b, _ := base64.StdEncoding.DecodeString(strings.Fields(l)[2])
			f.mu.Lock()
			f.auth = strings.ReplaceAll(string(b), "\x00", "|")
			f.mu.Unlock()
			say("235 ok")
		case "MAIL":
			say("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.rcpt = append(f.rcpt, l)
			f.mu.Unlock()
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				d, err := r.ReadString('\n')
				if err != nil || d == ".\r\n" {
					break
				}
				b.WriteString(d)
			}
			f.mu.Lock()
			f.mails = append(f.mails, b.String())
			f.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestEmailTarget(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := newFakeSMTP(t)
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte("s3cret\n"), 0o600)
	def := &Notifier{Store: e.st, MinSeverity: store.SeverityWarning, PublicURL: "https://lg.example", Metrics: e.d.Metrics, Log: e.d.Log}
	n, err := ParseEmailTarget("name=ops,to=a@example.net,b@example.net,from=lastgasp@example.net,smtp="+f.ln.Addr().String()+
		",user=lg,password-file="+pw, def)
	if err != nil {
		t.Fatal(err)
	}
	n.init()
	e.add(t, "h", "b1", "kmsg", e.t0, "booting", "Kernel panic - not syncing: Fatal exception")
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mails) != 1 || len(f.rcpt) != 2 || f.auth != "|lg|s3cret" {
		t.Fatalf("mails %d rcpt %v auth %q", len(f.mails), f.rcpt, f.auth)
	}
	m := f.mails[0]
	for _, want := range []string{
		"Subject: [critical] h kernel error (panic)",
		"To: a@example.net, b@example.net",
		"Content-Type: text/plain; charset=utf-8",
		"Details: https://lg.example/#incident=1",
		"Last kernel lines received:",
		"booting\r\n[    0.000000] Kernel panic",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("mail misses %q:\n%s", want, m)
		}
	}
	l, _ := e.st.Incidents(ctx, store.IncidentFilter{})
	if alertOf(l[0], "ops") != store.AlertSent {
		t.Fatalf("alert state %v", l[0].Alerts)
	}
}

func TestParseEmailTarget(t *testing.T) {
	def := &Notifier{MinSeverity: store.SeverityWarning, RateLimit: time.Minute}
	n, err := ParseEmailTarget("to=ops@example.net,smtp=mail.example.net:587", def)
	if err != nil || n.Name != "email" || n.Email.SMTP != "mail.example.net:587" || len(n.Email.To) != 1 ||
		!strings.HasPrefix(n.Email.From, "lastgasp@") || n.RateLimit != time.Minute {
		t.Fatalf("got %+v %+v %v", n, n.Email, err)
	}
	for _, bad := range []string{"", "to=ops@example.net", "smtp=mail:25", "to=nope,smtp=mail:25", "to=a@x,smtp=mail",
		"to=a@x,smtp=mail:25,user=u", "to=a@x,smtp=mail:25,format=slack", "name=x,y,to=a@x,smtp=m:25", "to=a@x,smtp=m:25,password-file=/missing",
		"to=a@x,smtp=m:25,ca-file=/missing"} {
		if _, err := ParseEmailTarget(bad, def); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestShortSilentBlipIsSkipped(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &hook{}
	srv := newHook(t, h)
	n := &Notifier{Store: e.st, Name: "hook", URL: srv, MinSeverity: store.SeverityWarning, Metrics: e.d.Metrics, Log: e.d.Log}
	n.init()
	e.add(t, "h", "b1", "kmsg", e.t0, "x")
	e.d.Tick(ctx, e.t0.Add(2*time.Minute))
	// The host is back before the target sent anything.
	e.d.Seen("h", "b1", e.t0.Add(3*time.Minute))
	if err := n.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.bodies) != 0 {
		t.Fatalf("sent %d alerts for a short blip", len(h.bodies))
	}
	l, _ := e.st.Incidents(ctx, store.IncidentFilter{})
	if alertOf(l[0], "hook") != store.AlertSkipped {
		t.Fatalf("alert states %v", l[0].Alerts)
	}
}

func TestEmailCAFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("not a certificate"), 0o600)
	def := &Notifier{}
	if _, err := ParseEmailTarget("to=a@x.net,smtp=m:587,ca-file="+bad, def); err == nil {
		t.Fatal("file without a certificate accepted")
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	n, err := ParseEmailTarget("to=a@x.net,smtp=m:587,ca-file="+ca, def)
	if err != nil || n.Email.TLS == nil || n.Email.TLS.RootCAs == nil {
		t.Fatalf("ca-file not loaded: %v", err)
	}
}
