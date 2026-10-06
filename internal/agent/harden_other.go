//go:build !linux

package agent

// Harden does nothing outside Linux.
func Harden(log *Logger, lockMemory bool) {}
