//go:build linux

package agent

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// mclOnFault locks future pages when first used instead of when mapped (Linux 4.4+). Not in package syscall.
const mclOnFault = 4

var mlockall = syscall.Mlockall

// Harden prepares the process to survive a failing machine. Every step is best effort.
func Harden(log *Logger, lockMemory bool) {
	// Without this, a write to a closed stderr pipe (journald died) kills the process.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)

	if lockMemory {
		inf := syscall.Rlimit{Cur: ^uint64(0), Max: ^uint64(0)}
		lockAll(log, syscall.Setrlimit(8 /* RLIMIT_MEMLOCK */, &inf) == nil)
	}

	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0); err != nil {
		log.Printf("harden: oom_score_adj: %v", err)
	}
}

// lockAll locks memory so code and data never need to be read back from a dead disk.
// unlimited tells whether the memlock limit could be raised.
func lockAll(log *Logger, unlimited bool) {
	// Every page mapped now, the binary included, is read in and locked.
	if err := mlockall(syscall.MCL_CURRENT); err != nil {
		log.Printf("harden: mlockall: %v", err)
		return
	}
	if !unlimited {
		// Locking future pages under a small limit would make memory allocation fail later.
		log.Printf("harden: memlock limit is fixed, only current pages are locked")
		return
	}
	// New pages are anonymous memory that never comes from disk, so locking them on first use is enough.
	// The Go runtime maps large heap areas it may never touch, which MCL_FUTURE alone would fill and lock.
	err := mlockall(syscall.MCL_FUTURE | mclOnFault)
	if errors.Is(err, syscall.EINVAL) {
		err = mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
	}
	if err != nil {
		log.Printf("harden: mlockall future pages: %v", err)
	}
}
