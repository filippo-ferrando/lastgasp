//go:build linux

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Magic numbers of file systems that live in memory only.
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// OpenStash maps the stash file at path with a ring of size bytes and returns the records a previous run
// of the same boot left unconfirmed. The file must be on tmpfs or ramfs, so the stash never writes to a disk.
func OpenStash(path string, size int, boot [16]byte, log *Logger) (*Stash, []Item, error) {
	if size < MinStash || size > MaxStash {
		return nil, nil, fmt.Errorf("stash size must be between %d and %d bytes", MinStash, MaxStash)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return nil, nil, err
	}
	// The field is int32 on 32 bit systems, where the ramfs magic looks negative.
	if t := uint32(fs.Type); t != tmpfsMagic && t != ramfsMagic {
		return nil, nil, fmt.Errorf("stash: %s is not on tmpfs or ramfs, refusing to write records to a disk", dir)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	want := int64(stashHeader + size)
	var items []Item
	if old := st.Size(); old >= stashHeader+MinStash && old <= stashHeader+MaxStash {
		mem, err := syscall.Mmap(int(f.Fd()), 0, int(old), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return nil, nil, err
		}
		items, err = newStash(mem, nil).recover(boot)
		if err != nil && err != errStashFormat {
			log.Printf("stash: %v, starting empty", err)
		}
		syscall.Munmap(mem)
	}
	if st.Size() != want {
		if err := f.Truncate(want); err != nil {
			return nil, nil, err
		}
	}
	// Space is reserved now: writing to a mapped page tmpfs has no room for would kill the agent with SIGBUS.
	if err := syscall.Fallocate(int(f.Fd()), 0, 0, want); err != nil {
		return nil, nil, fmt.Errorf("stash: reserve %d bytes: %w", want, err)
	}
	mem, err := syscall.Mmap(int(f.Fd()), 0, int(want), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	s := newStash(mem, func() error { return syscall.Munmap(mem) })
	s.reset(boot)
	return s, items, nil
}
