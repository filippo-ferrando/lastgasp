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
	"lastgasp/internal/wire"
)

func main() {
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
	)
	flag.Parse()
	log := agent.NewLogger(os.Stderr, 256)

	// Everything is read at start, while the disk still works.
	cfg := agent.Config{
		DNSServer: *dns, KmsgPath: *kmsg, PstoreDir: *pstore, BootIDPath: *bootID,
		BufferSize: *buffer, Rate: *rate, Heartbeat: *heartbeat, WaitAck: *waitAck, ResolveEvery: *resolve, MaxPstoreFile: 1 << 20,
	}
	for _, s := range strings.Split(*servers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			cfg.Servers = append(cfg.Servers, s)
		}
	}
	if len(cfg.Servers) == 0 {
		fatal("-server is required")
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
	if !wire.ValidHost(cfg.Host) {
		fatal("hostname %q is not valid: at most %d bytes of UTF-8, no spaces or control characters, use -hostname", cfg.Host, wire.MaxHostLen)
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
