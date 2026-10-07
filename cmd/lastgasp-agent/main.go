// Command lastgasp-agent sends kernel logs to lastgasp servers over encrypted UDP.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"lastgasp/internal/agent"
	"lastgasp/internal/version"
	"lastgasp/internal/wire"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		os.Exit(enroll(os.Args[2:]))
	}
	var (
		servers   = flag.String("server", "", "comma separated list of host:port servers (required)")
		keyFile   = flag.String("key-file", "", "file holding the hex key (or set LASTGASP_KEY)")
		host      = flag.String("hostname", "", "name sent to the server (default: kernel hostname)")
		dns       = flag.String("dns", "", "DNS server ip:port to use instead of /etc/resolv.conf")
		kmsg      = flag.String("kmsg", "/dev/kmsg", "kernel log device")
		pstore    = flag.String("pstore", "/sys/fs/pstore", "pstore directory, empty to disable")
		bootID    = flag.String("boot-id", "/proc/sys/kernel/random/boot_id", "boot id file")
		buffer    = flag.Int("buffer", 16384, "records kept in memory while servers are unreachable")
		rate      = flag.Int("rate", 2000, "max packets per second, 0 for no limit")
		heartbeat = flag.Duration("heartbeat", 5*time.Second, "interval between heartbeats")
		waitAck   = flag.Bool("wait-ack", true, "hold records until a server answers a heartbeat (needs -heartbeat > 0)")
		resolve   = flag.Duration("resolve-every", time.Minute, "interval between DNS refreshes")
		mlock     = flag.Bool("mlock", true, "lock all memory so the agent never reads from disk again")
		memLimit  = flag.Int64("memory-limit", 64<<20, "soft Go memory limit in bytes")
		stash     = flag.String("stash", "/run/lastgasp/agent.stash", "file on tmpfs that keeps unconfirmed records across agent restarts, empty to disable")
		stashSize = flag.Int("stash-size", 8<<20, "stash size in bytes")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("lastgasp-agent", version.String())
		return
	}
	log := agent.NewLogger(os.Stderr, 256)

	// Everything is read at start, while the disk still works.
	cfg := agent.Config{
		DNSServer: *dns, KmsgPath: *kmsg, PstoreDir: *pstore, BootIDPath: *bootID,
		BufferSize: *buffer, Rate: *rate, Heartbeat: *heartbeat, WaitAck: *waitAck, ResolveEvery: *resolve, MaxPstoreFile: 1 << 20,
		StashPath: *stash, StashSize: *stashSize,
	}
	for _, s := range strings.Split(*servers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			cfg.Servers = append(cfg.Servers, s)
		}
	}
	keyHex := os.Getenv("LASTGASP_KEY")
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			fatal("read key: %v", err)
		}
		keyHex = string(b)
	}
	if keyHex == "" {
		fatal("a key is required: use -key-file or LASTGASP_KEY")
	}
	key, err := wire.ParseKey(keyHex)
	if err != nil {
		fatal("%v", err)
	}
	cfg.Key = key
	cfg.Host = *host
	if cfg.Host == "" {
		if cfg.Host, err = os.Hostname(); err != nil || cfg.Host == "" {
			fatal("cannot read hostname, use -hostname")
		}
	}
	if err := cfg.Validate(); err != nil {
		fatal("%v", err)
	}
	if *memLimit <= 0 {
		fatal("-memory-limit must be above 0")
	}

	debug.SetMemoryLimit(*memLimit)
	agent.Harden(log, *mlock)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := agent.Run(ctx, cfg, log); err != nil {
		fatal("%v", err)
	}
	// Give the logger a moment to flush.
	time.Sleep(100 * time.Millisecond)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lastgasp-agent: "+format+"\n", args...)
	os.Exit(1)
}

// enroll gets a key from the server with a join token and saves it, for the install script.
func enroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	servers := fs.String("server", "", "host:port of the server, the first of a comma separated list is used (required)")
	token := fs.String("token", "", "join token from the server web UI (required)")
	host := fs.String("hostname", "", "name sent to the server (default: kernel hostname)")
	keyFile := fs.String("key-file", "/etc/lastgasp/agent.key", "where to save the key")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait for the server")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: lastgasp-agent enroll -server HOST:PORT -token TOKEN [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	server, _, _ := strings.Cut(*servers, ",")
	if server == "" || *token == "" {
		fs.Usage()
		return 2
	}
	name := *host
	if name == "" {
		var err error
		if name, err = os.Hostname(); err != nil {
			fmt.Fprintln(os.Stderr, "lastgasp-agent: cannot read hostname, use -hostname")
			return 1
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	key, err := agent.Enroll(ctx, strings.TrimSpace(server), name, strings.TrimSpace(*token))
	if err != nil {
		fmt.Fprintln(os.Stderr, "lastgasp-agent: enroll:", err)
		return 1
	}
	if err := agent.WriteKeyFile(*keyFile, key); err != nil {
		fmt.Fprintln(os.Stderr, "lastgasp-agent: enroll:", err)
		return 1
	}
	fmt.Printf("enrolled %s with %s, key saved to %s\n", name, server, *keyFile)
	return 0
}
