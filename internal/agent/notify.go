package agent

import (
	"net"
	"os"
)

// notifyReady tells systemd the agent started (sd_notify READY=1), when it runs as a Type=notify unit.
func notifyReady(log *Logger) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	// A leading @ is an abstract socket, written with a leading NUL byte.
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		log.Printf("notify systemd: %v", err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		log.Printf("notify systemd: %v", err)
	}
}
