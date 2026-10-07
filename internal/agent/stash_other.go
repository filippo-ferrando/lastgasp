//go:build !linux

package agent

import "errors"

// OpenStash is only supported on Linux.
func OpenStash(path string, size int, boot [16]byte, log *Logger) (*Stash, []Item, error) {
	return nil, nil, errors.New("stash: only supported on Linux")
}
