//go:build linux

package agent

import (
	"os"
	"os/signal"
	"syscall"
)

// Harden prepares the process to survive a failing machine. Every step is best effort.
func Harden(log *Logger, lockMemory bool) {
	// Without this, a write to a closed stderr pipe (journald died) kills the process.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)

	if lockMemory {
		// Locked pages are never evicted, so code and data never need to be read back from a dead disk.
		inf := syscall.Rlimit{Cur: ^uint64(0), Max: ^uint64(0)}
		if err := syscall.Setrlimit(8 /* RLIMIT_MEMLOCK */, &inf); err == nil {
			if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
				log.Printf("harden: mlockall: %v", err)
			}
		} else if err := syscall.Mlockall(syscall.MCL_CURRENT); err != nil {
			// Locking future pages under a small limit would make memory allocation fail later.
			log.Printf("harden: cannot raise memlock limit, mlockall current pages: %v", err)
		} else {
			log.Printf("harden: memlock limit is fixed, only current pages are locked")
		}
	}

	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0); err != nil {
		log.Printf("harden: oom_score_adj: %v", err)
	}
}
