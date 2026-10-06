// Command lastgasp-server collects agent packets, stores logs and serves the web UI and metrics.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"golang.org/x/term"

	"lastgasp/internal/incident"
	"lastgasp/internal/server"
	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

func main() {
	var (
		listen   = flag.String("listen", ":5140", "UDP address for agent packets")
		httpAddr = flag.String("http", ":8080", "HTTP address for the web UI, API and /metrics")
		dsn      = flag.String("db", "lastgasp.db", "SQLite file, or a postgres:// URL")
		keyFile  = flag.String("key-file", "", "file with \"host hexkey\" lines, \"*\" matches any host (required)")
		stale    = flag.Duration("stale-after", 30*time.Second, "time without packets before a host is shown as down")
		rcvBuf   = flag.Int("rcvbuf", 8<<20, "UDP receive buffer in bytes")
		retain   = flag.Duration("retain", 0, "delete records, closed incidents and agent runs older than this, 0 keeps everything")

		rulesFile    = flag.String("rules", "", "file with extra incident rules (\"name severity regexp\" or \"name off\")")
		silentAfter  = flag.Duration("silent-after", 2*time.Minute, "time without packets before a silent incident is opened, 0 to disable")
		crashWait    = flag.Duration("crash-wait", 2*time.Minute, "time after a reboot to wait for pstore lines before deciding crash or reboot")
		ctxLines     = flag.Int("incident-context", 200, "log lines kept as context of an incident")
		resolveAfter = flag.Duration("resolve-after", 30*time.Minute, "close a kernel error incident as resolved after this long without a new matching line, 0 never")
		alertFormat  = flag.String("alert-format", "json", "default alert body: json, or slack for Slack and Mattermost")
		alertKey     = flag.String("alert-key-file", "", "default hex key file used to sign alerts in the X-Lastgasp-Signature header")
		alertMin     = flag.String("alert-min-severity", "warning", "default lowest severity that sends an alert: info, warning or critical")
		alertRate    = flag.Duration("alert-rate-limit", 10*time.Minute, "default limit of one alert per host, incident kind and rule in this time")
		authFile     = flag.String("auth-file", "", "users and API tokens for the web UI and API (\"name role hash\" lines), empty for no login")
		authProxy    = flag.String("auth-proxy-header", "", "header with the client address set by a reverse proxy, like X-Forwarded-For")
		authTrusted  = flag.String("auth-trusted-proxies", "127.0.0.1,::1", "comma separated addresses or CIDR prefixes allowed to set -auth-proxy-header")
		authMetrics  = flag.Bool("auth-metrics", false, "also require a login for /metrics")
		publicURL    = flag.String("public-url", "", "web UI address used for links in alerts, for example https://lastgasp.example.net")
	)
	var webhooks, emails stringList
	flag.Var(&webhooks, "alert-webhook", "alert target, repeatable: a URL, or \"name=N,format=F,min=S,key-file=P,rate=D,url=URL\"")
	flag.Usage = usage
	flag.Var(&emails, "alert-email", "email alert target, repeatable: \"to=A,B,smtp=HOST:PORT\" plus name, min, rate, from, user, password-file")
	flag.Parse()
	if flag.NArg() > 0 {
		os.Exit(command(flag.Args()))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	// Caught from the start, as the default action of SIGHUP would kill the server while it starts.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	switch {
	case *stale <= 0:
		fail("start", errors.New("-stale-after must be above 0"))
	case *rcvBuf <= 0:
		fail("start", errors.New("-rcvbuf must be above 0"))
	case *retain < 0 || *silentAfter < 0 || *crashWait < 0 || *resolveAfter < 0 || *alertRate < 0:
		fail("start", errors.New("durations must not be negative"))
	case *retain > 0 && *retain < time.Hour:
		fail("start", errors.New("-retain must be at least 1h, or 0 to keep everything"))
	case *ctxLines < 1 || *ctxLines > 10000:
		fail("start", errors.New("-incident-context must be between 1 and 10000"))
	}
	trusted, err := server.ParsePrefixes(*authTrusted)
	if err != nil {
		fail("start", fmt.Errorf("-auth-trusted-proxies: %w", err))
	}

	if *keyFile == "" {
		fail("start", errors.New("-key-file is required"))
	}
	keys, err := server.OpenKeyFile(*keyFile)
	if err != nil {
		fail("load keys", err)
	}
	rules, err := incident.LoadRules(*rulesFile)
	if err != nil {
		fail("load rules", err)
	}
	minSev, err := store.ParseSeverity(*alertMin)
	if err != nil {
		fail("start", err)
	}
	var signKey []byte
	if *alertKey != "" {
		b, err := os.ReadFile(*alertKey)
		if err != nil {
			fail("read alert key", err)
		}
		if signKey, err = wire.ParseKey(string(b)); err != nil {
			fail("read alert key", err)
		}
	}
	st, err := store.Open(*dsn)
	if err != nil {
		fail("open database", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tr := server.NewTracker()
	if err := server.LoadStreams(ctx, st, tr); err != nil {
		fail("load stream state", err)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := server.NewMetrics(reg, tr, *stale)
	in := server.NewIngestor(st, tr, keys, metrics, log)

	im := incident.NewMetrics(reg)
	det := incident.NewDetector(st, rules, incident.Config{SilentAfter: *silentAfter, CrashWait: *crashWait, Context: *ctxLines,
		ResolveAfter: *resolveAfter}, im, log)
	def := &incident.Notifier{Store: st, Format: *alertFormat, Key: signKey, PublicURL: *publicURL, MinSeverity: minSev,
		RateLimit: *alertRate, Metrics: im, Log: log}
	var targets incident.Notifiers
	names := map[string]bool{}
	specs := make([]func() (*incident.Notifier, error), 0, len(webhooks)+len(emails))
	for _, spec := range webhooks {
		specs = append(specs, func() (*incident.Notifier, error) { return incident.ParseTarget(spec, def) })
	}
	for _, spec := range emails {
		specs = append(specs, func() (*incident.Notifier, error) { return incident.ParseEmailTarget(spec, def) })
	}
	for _, parse := range specs {
		n, err := parse()
		if err != nil {
			fail("alert target", err)
		}
		if names[n.Name] {
			fail("alert target", fmt.Errorf("two targets named %q, set name=... on each", n.Name))
		}
		names[n.Name] = true
		targets = append(targets, n)
	}
	var seen []incident.HostSeen
	for _, h := range tr.Hosts(time.Now(), *stale) {
		seen = append(seen, incident.HostSeen{Host: h.Host, BootID: h.BootID})
	}
	if err := det.Load(ctx, seen, time.Now()); err != nil {
		fail("load incidents", err)
	}
	in.Detector = det
	var workers sync.WaitGroup
	if len(targets) > 0 {
		det.Wake = targets.Wake
		workers.Go(func() { targets.Run(ctx) })
	}
	workers.Go(func() { det.Run(ctx) })
	if *retain > 0 {
		r := &server.Retention{Store: st, Tracker: tr, Detector: det, Metrics: metrics, Log: log, Age: *retain, Every: time.Hour}
		workers.Go(func() { r.Run(ctx) })
	}

	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		fail("listen udp", err)
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		if err := uc.SetReadBuffer(*rcvBuf); err != nil {
			log.Warn("set udp receive buffer", "err", err)
		}
	}
	go in.Listen(conn)
	done := make(chan struct{})
	go func() { in.Run(ctx); close(done) }()

	api := &server.API{Store: st, Tracker: tr, StaleAfter: *stale, Gatherer: reg, Context: *ctxLines, AuthMetrics: *authMetrics}
	if *authFile != "" {
		if api.Auth, err = server.OpenAuth(*authFile); err != nil {
			fail("load auth file", err)
		}
		api.Auth.Failures, api.Auth.Blocked, api.Auth.ProxyHeader = metrics.AuthFailures, metrics.AuthBlocked, *authProxy
		api.Auth.TrustedProxies = trusted
	} else if !server.Loopback(*httpAddr) {
		log.Warn("the web UI and API have no login and listen on a public address, use -auth-file", "http", *httpAddr)
	}

	// SIGHUP reloads the key file, the rules and the auth file. On error the old ones stay in use.
	go func() {
		for range hup {
			if err := keys.Reload(); err != nil {
				log.Error("reload keys, keeping the old ones", "err", err)
				metrics.KeyReloads.WithLabelValues("error").Inc()
			} else {
				log.Info("keys reloaded", "entries", keys.Hosts())
				metrics.KeyReloads.WithLabelValues("ok").Inc()
			}
			if api.Auth != nil {
				if err := api.Auth.Reload(); err != nil {
					log.Error("reload auth file, keeping the old users", "err", err)
				} else {
					log.Info("auth file reloaded", "users", api.Auth.Users())
				}
			}
			if r, err := incident.LoadRules(*rulesFile); err != nil {
				log.Error("reload rules, keeping the old ones", "err", err)
			} else {
				det.SetRules(r)
			}
		}
	}()
	// No write timeout, as /api/download streams large files.
	srv := &http.Server{Addr: *httpAddr, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	// An HTTP error stops the server through the normal shutdown, so state is saved and the database closed.
	exitCode := 0
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
			exitCode = 1
			stop()
		}
	}()
	log.Info("lastgasp-server started", "udp", conn.LocalAddr().String(), "http", *httpAddr, "db", redact(*dsn))

	// Shutdown order: stop taking packets and requests, store what is queued, let the workers save, then close the database.
	<-ctx.Done()
	log.Info("shutting down")
	conn.Close()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdown)
	<-done
	workers.Wait()
	det.Flush(context.Background())
	log.Info("stopped")
	if exitCode != 0 {
		st.Close()
		os.Exit(exitCode)
	}
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage:\n  lastgasp-server [flags]\n  lastgasp-server user NAME ROLE    print an auth file line, asks for the password\n")
	fmt.Fprintf(out, "  lastgasp-server token NAME ROLE   print a new API token and its auth file line\nROLE is viewer or admin.\n\nFlags:\n")
	flag.PrintDefaults()
}

// command runs the helper commands that create auth file lines.
func command(args []string) int {
	if len(args) != 3 || (args[0] != "user" && args[0] != "token") {
		usage()
		return 2
	}
	role, err := server.ParseRole(args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if args[0] == "token" {
		token, line := server.NewToken(args[1], role)
		fmt.Printf("token: %s\nauth file line: %s\n", token, line)
		return 0
	}
	password, err := readPassword()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	line, err := server.HashPassword(args[1], role, password)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(line)
	return 0
}

// readPassword asks twice on a terminal, without echo. From a pipe it reads one line.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "password: ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "again: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("the passwords do not match")
	}
	return string(a), nil
}

// stringList is a flag that can be given more than once.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, " ") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// redact hides the password in a postgres URL.
func redact(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" {
		return u.Redacted()
	}
	return dsn
}
