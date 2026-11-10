package incident

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"

	"lastgasp/internal/store"
)

// Email is the SMTP setup of an email target.
type Email struct {
	SMTP     string // host:port, port 465 uses TLS from the start, other ports need STARTTLS
	From     string
	To       []string
	User     string // empty for no login
	Password string
	// TLS is used for the SMTP connection, nil for the system defaults.
	TLS *tls.Config
}

// emailLines is the number of kernel and pstore lines put in an email.
const emailLines = 40

func (n *Notifier) sendEmail(ctx context.Context, p *store.PendingAlert) error {
	msg, err := n.emailMessage(ctx, p)
	if err != nil {
		return err
	}
	return n.Email.deliver(ctx, msg)
}

// emailMessage builds the mail: headers, the incident, then the pstore lines and the last kernel lines.
func (n *Notifier) emailMessage(ctx context.Context, p *store.PendingAlert) ([]byte, error) {
	inc := &p.Incident
	var body bytes.Buffer
	line := func(format string, args ...any) {
		s := strings.ToValidUTF8(fmt.Sprintf(format, args...), "")
		// SMTP allows 998 bytes per line.
		if len(s) > 900 {
			s = strings.ToValidUTF8(s[:900], "") + "..."
		}
		body.WriteString(s + "\r\n")
	}
	line("%s", Text(inc, p.Resolve, ""))
	line("")
	line("Host:    %s", inc.Host)
	line("Boot:    %s", inc.BootID)
	kind := inc.Kind
	if inc.Rule != "" {
		kind += " (" + inc.Rule + ")"
	}
	line("Kind:    %s, %s", kind, inc.Severity)
	line("Opened:  %s", inc.OpenedAt.Format(time.RFC3339))
	if !inc.ClosedAt.IsZero() {
		line("Closed:  %s", inc.ClosedAt.Format(time.RFC3339))
	}
	line("Count:   %d", inc.Count)
	if l := n.link(inc.ID); l != "" {
		line("Details: %s", l)
	}
	if !p.Resolve {
		if inc.Kind == KindCrash || inc.Kind == KindReboot {
			recs, err := n.Store.Query(ctx, store.Filter{Host: inc.Host, BootID: inc.BootID, Source: "pstore", MaxLevel: -1, Limit: emailLines})
			if err != nil {
				return nil, err
			}
			if len(recs) > 0 {
				line("")
				line("Last lines saved by the kernel before the reboot (pstore):")
				writeRecords(line, recs)
			}
		}
		if inc.LastRecordID > 0 {
			recs, err := n.Store.Query(ctx, store.Filter{Host: inc.Host, BootID: inc.BootID, Sources: store.LiveSources, MaxLevel: -1,
				BeforeID: inc.LastRecordID + 1, Limit: emailLines})
			if err != nil {
				return nil, err
			}
			line("")
			line("Last kernel lines received:")
			writeRecords(line, recs)
		}
	}

	e := n.Email
	var head bytes.Buffer
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(Headline(inc, p.Resolve))
	for _, h := range [][2]string{
		{"From", e.From},
		{"To", strings.Join(e.To, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", subject)},
		{"Date", n.now().Format(time.RFC1123Z)},
		{"Message-ID", fmt.Sprintf("<lastgasp-%d-%d@%s>", inc.ID, n.now().UnixNano(), domain(e.From))},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "8bit"},
	} {
		head.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	head.WriteString("\r\n")
	return append(head.Bytes(), body.Bytes()...), nil
}

// writeRecords prints records oldest first. Queries return them newest first.
func writeRecords(line func(string, ...any), recs []store.Record) {
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		line("[%5d.%06d] %s", r.TsUsec/1e6, r.TsUsec%1e6, r.Message)
	}
}

func domain(addr string) string {
	if _, d, ok := strings.Cut(addr, "@"); ok {
		return strings.TrimSuffix(d, ">")
	}
	return "lastgasp"
}

// deliver sends one mail. A login is only sent over TLS, unless the server is on this machine.
func (e *Email) deliver(ctx context.Context, msg []byte) error {
	host, port, err := net.SplitHostPort(e.SMTP)
	if err != nil {
		return err
	}
	cfg := &tls.Config{ServerName: host}
	if e.TLS != nil {
		cfg = e.TLS.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if port == "465" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", e.SMTP)
	} else {
		conn, err = d.DialContext(ctx, "tcp", e.SMTP)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(time.Minute))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(cfg); err != nil {
				return err
			}
		} else if !loopbackHost(host) {
			return fmt.Errorf("smtp %s does not offer STARTTLS", e.SMTP)
		}
	}
	if e.User != "" {
		if err := c.Auth(smtp.PlainAuth("", e.User, e.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(e.From); err != nil {
		return err
	}
	for _, to := range e.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParseEmailTarget reads an -alert-email value: "to=a@x,b@y,smtp=host:port" plus optional
// name, min, rate, from, user, password-file and ca-file (to trust a private certificate authority). Options not given are taken from def.
func ParseEmailTarget(spec string, def *Notifier) (*Notifier, error) {
	n := &Notifier{Store: def.Store, Name: "email", PublicURL: def.PublicURL, MinSeverity: def.MinSeverity,
		RateLimit: def.RateLimit, Metrics: def.Metrics, Log: def.Log, Email: &Email{}}
	e := n.Email
	key := ""
	for _, part := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			// A part without "=" is one more recipient, as in "to=a@x,b@y".
			if key != "to" {
				return nil, fmt.Errorf("email option %q has no value", part)
			}
			k, v = "to", part
		}
		key = k
		switch k {
		case "name":
			n.Name = v
		case "min":
			sev, err := store.ParseSeverity(v)
			if err != nil {
				return nil, err
			}
			n.MinSeverity = sev
		case "rate":
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, err
			}
			n.RateLimit = d
		case "to":
			a, err := mail.ParseAddress(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("recipient %q: %w", v, err)
			}
			e.To = append(e.To, a.Address)
		case "from":
			a, err := mail.ParseAddress(v)
			if err != nil {
				return nil, fmt.Errorf("sender %q: %w", v, err)
			}
			e.From = a.Address
		case "smtp":
			if _, _, err := net.SplitHostPort(v); err != nil {
				return nil, fmt.Errorf("smtp %q: want host:port", v)
			}
			e.SMTP = v
		case "user":
			e.User = v
		case "ca-file":
			b, err := os.ReadFile(v)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				return nil, fmt.Errorf("ca-file %s: no PEM certificate found", v)
			}
			e.TLS = &tls.Config{RootCAs: pool}
		case "password-file":
			b, err := os.ReadFile(v)
			if err != nil {
				return nil, err
			}
			e.Password = strings.TrimRight(string(b), "\r\n")
		default:
			return nil, fmt.Errorf("unknown email option %q", k)
		}
	}
	if len(e.To) == 0 || e.SMTP == "" {
		return nil, fmt.Errorf("email target %q: to=... and smtp=host:port are required", spec)
	}
	if e.User != "" && e.Password == "" {
		return nil, fmt.Errorf("email target %s: user needs password-file", n.Name)
	}
	if e.From == "" {
		h, _ := os.Hostname()
		e.From = "lastgasp@" + h
	}
	return n, nil
}
