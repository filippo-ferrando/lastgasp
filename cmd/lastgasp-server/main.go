// Command lastgasp-server collects agent packets, stores logs and serves the web UI and metrics.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
	"lastgasp/internal/version"
	"lastgasp/internal/wire"
)

func main() {
	var (
		listen     = flag.String("listen", ":5140", "UDP address for agent packets")
		httpAddr   = flag.String("http", ":8080", "HTTP address for the web UI, API and /metrics")
		dsn        = flag.String("db", "lastgasp.db", "SQLite file, or a postgres:// URL")
		keyFile    = flag.String("key-file", "", "file with \"host hexkey\" lines, \"*\" matches any host, optional when agents enroll")
		stale      = flag.Duration("stale-after", 30*time.Second, "time without packets before a host is shown as down")
		rcvBuf     = flag.Int("rcvbuf", 8<<20, "UDP receive buffer in bytes")
		retain     = flag.Duration("retain", 0, "delete records, closed incidents and agent runs older than this, 0 keeps everything")
		retainInfo = flag.Duration("retain-info", 0, "delete records of level info and debug older than this, 0 to use -retain only")
		retainRecs = flag.Int("retain-records", 0, "keep at most this many records in total, oldest deleted first, 0 for no limit")
		retainHost = flag.Int("retain-host-records", 0, "keep at most this many records per host, oldest deleted first, 0 for no limit")
		retainSize = flag.String("retain-bytes", "0", "keep the records under this size (for example 20GiB), oldest deleted first, 0 for no limit")

		rulesFile    = flag.String("rules", "", "file with extra incident rules (\"name severity regexp\" or \"name off\")")
		silentAfter  = flag.Duration("silent-after", 2*time.Minute, "time without packets before a silent incident is opened, 0 to disable")
		crashWait    = flag.Duration("crash-wait", 2*time.Minute, "time after a reboot to wait for pstore lines before deciding crash or reboot")
		ctxLines     = flag.Int("incident-context", 200, "log lines kept as context of an incident")
		flapCount    = flag.Int("flap-count", 3, "reboots or returns from silence within -flap-window that open a flapping incident, 0 to disable")
		flapWindow   = flag.Duration("flap-window", time.Hour, "time window of -flap-count")
		groupHosts   = flag.Int("group-min-hosts", 3, "hosts that reboot or go silent within -group-window to share one alert, 0 to disable")
		groupWindow  = flag.Duration("group-window", 2*time.Minute, "time window of -group-min-hosts")
		resolveAfter = flag.Duration("resolve-after", 30*time.Minute, "close a kernel error incident as resolved after this long without a new matching line, 0 never")
		alertFormat  = flag.String("alert-format", "json", "default alert body: json, slack for Slack and Mattermost, or alertmanager for the Alertmanager v2 API")
		alertKey     = flag.String("alert-key-file", "", "default hex key file used to sign alerts in the X-Lastgasp-Signature header")
		alertMin     = flag.String("alert-min-severity", "warning", "default lowest severity that sends an alert: info, warning or critical")
		alertRate    = flag.Duration("alert-rate-limit", 10*time.Minute, "default limit of one alert per host, incident kind and rule in this time")
		authFile     = flag.String("auth-file", "", "users and API tokens for the web UI and API (\"name role hash\" lines), empty for no login")
		authProxy    = flag.String("auth-proxy-header", "", "header with the client address set by a reverse proxy, like X-Forwarded-For")
		authTrusted  = flag.String("auth-trusted-proxies", "127.0.0.1,::1", "comma separated addresses or CIDR prefixes allowed to set -auth-proxy-header")
		authMetrics  = flag.Bool("auth-metrics", false, "also require a login for /metrics")
		sessionTTL   = flag.Duration("session-ttl", 7*24*time.Hour, "how long a login on the web UI lasts")
		publicURL    = flag.String("public-url", "", "web UI address used for links in alerts, for example https://lastgasp.example.net")
		showVer      = flag.Bool("version", false, "print the version and exit")
		agentAddr    = flag.String("agent-address", "", "host:port agents send to, used in install commands. Default: the -public-url host with the -listen port")
		requireFS    = flag.Bool("require-forward-secrecy", false, "refuse packets before version 5, which have no forward secrecy (agents with -wait-ack=false or -forward-secrecy=false)")
		ncListen     = flag.String("netconsole-listen", "", "UDP address for extended netconsole lines sent by the kernel itself, like :6666. Empty to disable")
		ncFrom       = flag.String("netconsole-from", "", "comma separated addresses or CIDR prefixes allowed to send netconsole lines")
		ncHosts      = flag.String("netconsole-hosts", "", "file with \"ip host\" lines naming the senders of netconsole lines")
		ncDelay      = flag.Duration("netconsole-delay", 10*time.Second, "time a netconsole line waits, so the agent copy of it wins")
		repoURL      = flag.String("repo-url", "https://git.fferrando.cc/rdfilippo/lastgasp", "repository whose releases hold the agent and its installer")
	)
	var webhooks, emails, telegrams stringList
	flag.Var(&webhooks, "alert-webhook", "alert target, repeatable: a URL, or \"name=N,format=F,min=S,key-file=P,rate=D,url=URL\"")
	flag.Usage = usage
	flag.Var(&telegrams, "alert-telegram", "Telegram alert target, repeatable: \"chat=ID,token-file=PATH\" plus name, min, rate, api")
	flag.Var(&emails, "alert-email", "email alert target, repeatable: \"to=A,B,smtp=HOST:PORT\" plus name, min, rate, from, user, password-file")
	flag.Parse()
	if *showVer {
		fmt.Println("lastgasp-server", version.String())
		return
	}
	if flag.NArg() > 0 {
		os.Exit(command(flag.Args()))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
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
	case *retain > 0 && *retain < time.Hour, *retainInfo > 0 && *retainInfo < time.Hour:
		fail("start", errors.New("-retain and -retain-info must be at least 1h, or 0"))
	case *retainInfo < 0 || *retainRecs < 0 || *retainHost < 0:
		fail("start", errors.New("retention limits must not be negative"))
	case *sessionTTL < time.Minute:
		fail("start", errors.New("-session-ttl must be at least 1m"))
	case *flapCount < 0 || *flapCount == 1 || *flapCount > 100 || *flapWindow < time.Minute:
		fail("start", errors.New("-flap-count must be 0 or between 2 and 100, -flap-window at least 1m"))
	case *groupHosts < 0 || *groupHosts == 1 || *groupWindow <= 0:
		fail("start", errors.New("-group-min-hosts must be 0 or at least 2, -group-window above 0"))
	case *ctxLines < 1 || *ctxLines > 10000:
		fail("start", errors.New("-incident-context must be between 1 and 10000"))
	}
	ncPrefixes, err := server.ParsePrefixes(*ncFrom)
	if err != nil {
		fail("start", fmt.Errorf("-netconsole-from: %w", err))
	}
	var ncHostMap *server.NetconsoleHosts
	if *ncListen != "" {
		if len(ncPrefixes) == 0 || *ncHosts == "" || *ncDelay < time.Second {
			fail("start", errors.New("-netconsole-listen needs -netconsole-from, -netconsole-hosts and a -netconsole-delay of at least 1s"))
		}
		if ncHostMap, err = server.LoadNetconsoleHosts(*ncHosts); err != nil {
			fail("load netconsole hosts", err)
		}
	}
	maxBytes, err := server.ParseSize(*retainSize)
	if err != nil {
		fail("start", fmt.Errorf("-retain-bytes: %w", err))
	}
	trusted, err := server.ParsePrefixes(*authTrusted)
	if err != nil {
		fail("start", fmt.Errorf("-auth-trusted-proxies: %w", err))
	}

	var keyFileRing *server.KeyFile
	if *keyFile != "" {
		if keyFileRing, err = server.OpenKeyFile(*keyFile); err != nil {
			fail("load keys", err)
		}
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
	enrolled := server.NewEnrolledKeys()
	if err := enrolled.Load(ctx, st); err != nil {
		fail("load enrolled agents", err)
	}
	keys := &server.Keys{File: keyFileRing, Enrolled: enrolled}
	if keyFileRing == nil || keyFileRing.Hosts() == 0 {
		log.Info("no key in a key file, only enrolled agents are accepted")
	}
	in := server.NewIngestor(st, tr, keys, metrics, log)
	in.RequireFS = *requireFS
	enroller := &server.Enroller{Store: st, Keys: keys, Log: log, Results: metrics.Enrollments}
	in.Enroller = enroller

	im := incident.NewMetrics(reg)
	det := incident.NewDetector(st, rules, incident.Config{SilentAfter: *silentAfter, CrashWait: *crashWait, Context: *ctxLines,
		ResolveAfter: *resolveAfter, FlapCount: *flapCount, FlapWindow: *flapWindow,
		GroupMinHosts: *groupHosts, GroupWindow: *groupWindow}, im, log)
	def := &incident.Notifier{Store: st, Format: *alertFormat, Key: signKey, PublicURL: *publicURL, MinSeverity: minSev,
		RateLimit: *alertRate, Metrics: im, Log: log}
	var targets incident.Notifiers
	names := map[string]bool{}
	specs := make([]func() (*incident.Notifier, error), 0, len(webhooks)+len(emails)+len(telegrams))
	for _, spec := range webhooks {
		specs = append(specs, func() (*incident.Notifier, error) { return incident.ParseTarget(spec, def) })
	}
	for _, spec := range telegrams {
		specs = append(specs, func() (*incident.Notifier, error) { return incident.ParseTelegramTarget(spec, def) })
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
	self := &server.SelfCheck{Detector: det, Checks: server.ServerChecks(metrics, im), Every: 10 * time.Second}
	workers.Go(func() { self.Run(ctx) })
	r := &server.Retention{Store: st, Tracker: tr, Detector: det, Metrics: metrics, Log: log, Age: *retain,
		InfoAge: *retainInfo, MaxRecords: *retainRecs, MaxHostRecords: *retainHost, MaxBytes: maxBytes, Every: 10 * time.Minute}
	if r.Enabled() {
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
	enroller.Reply = func(b []byte, to net.Addr) { conn.WriteTo(b, to) }
	workers.Go(func() { enroller.Run(ctx) })
	go in.Listen(conn)
	var nc *server.Netconsole
	var ncConn net.PacketConn
	if *ncListen != "" {
		in.NetconsoleDelay = *ncDelay
		if ncConn, err = net.ListenPacket("udp", *ncListen); err != nil {
			fail("listen netconsole", err)
		}
		nc = &server.Netconsole{In: in, From: ncPrefixes}
		nc.Hosts.Store(ncHostMap)
		go nc.Listen(ncConn)
	}
	done := make(chan struct{})
	go func() { in.Run(ctx); close(done) }()

	ready := func(ctx context.Context) error {
		if err := st.Ping(ctx); err != nil {
			return fmt.Errorf("database: %w", err)
		}
		return in.Ready()
	}
	install := server.Install{AgentAddress: server.AgentAddress(*agentAddr, *publicURL, conn.LocalAddr().String()),
		RepoURL: *repoURL, Version: version.String()}
	api := &server.API{Ready: ready, Enrolled: enrolled, Install: install, Store: st, Tracker: tr, StaleAfter: *stale, Gatherer: reg, Context: *ctxLines, AuthMetrics: *authMetrics,
		Detector: det}
	if *authFile != "" {
		if api.Auth, err = server.OpenAuth(*authFile); err != nil {
			fail("load auth file", err)
		}
		api.Auth.Failures, api.Auth.Blocked, api.Auth.ProxyHeader = metrics.AuthFailures, metrics.AuthBlocked, *authProxy
		api.Auth.TrustedProxies = trusted
		api.Auth.Sessions, api.Auth.SessionTTL = st, *sessionTTL
		api.Auth.SecureCookie = strings.HasPrefix(*publicURL, "https://")
	} else if !server.Loopback(*httpAddr) {
		log.Warn("the web UI and API have no login and listen on a public address, use -auth-file", "http", *httpAddr)
	}

	// SIGHUP reloads the key file, the rules, the auth file and the netconsole hosts. On error the old ones stay in use.
	go func() {
		for range hup {
			if keyFileRing == nil {
				// Only enrolled agents, no key file to read.
			} else if err := keyFileRing.Reload(); err != nil {
				log.Error("reload keys, keeping the old ones", "err", err)
				metrics.KeyReloads.WithLabelValues("error").Inc()
			} else {
				log.Info("keys reloaded", "entries", keyFileRing.Hosts())
				metrics.KeyReloads.WithLabelValues("ok").Inc()
			}
			if api.Auth != nil {
				if err := api.Auth.Reload(); err != nil {
					log.Error("reload auth file, keeping the old users", "err", err)
				} else {
					log.Info("auth file reloaded", "users", api.Auth.Users())
				}
			}
			if nc != nil {
				if h, err := server.LoadNetconsoleHosts(*ncHosts); err != nil {
					log.Error("reload netconsole hosts, keeping the old ones", "err", err)
				} else {
					nc.Hosts.Store(h)
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
	log.Info("lastgasp-server started", "version", version.String(), "udp", conn.LocalAddr().String(), "http", *httpAddr, "db", redact(*dsn))

	// Shutdown order: stop taking packets and requests, store what is queued, let the workers save, then close the database.
	<-ctx.Done()
	log.Info("shutting down")
	conn.Close()
	if ncConn != nil {
		ncConn.Close()
	}
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
	fmt.Fprintf(out, "  lastgasp-server token NAME ROLE   print a new API token and its auth file line\n")
	fmt.Fprintf(out, "  lastgasp-server health [URL]      exit 0 when URL answers 200, default %s\nROLE is viewer or admin.\n\nFlags:\n", healthURL)
	flag.PrintDefaults()
}

// healthURL is checked by the health command, for container health checks.
const healthURL = "http://127.0.0.1:8080/readyz"

// command runs the helper commands: auth file lines and the health check.
func command(args []string) int {
	if args[0] == "health" && len(args) <= 2 {
		u := healthURL
		if len(args) == 2 {
			u = args[1]
		}
		return health(u)
	}
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

// health checks one URL, as distroless images have no curl.
func health(u string) int {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "%s: %s %s", u, resp.Status, b)
		return 1
	}
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
