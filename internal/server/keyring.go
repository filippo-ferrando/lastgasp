// Package server receives agent packets, tracks gaps and serves the web UI and metrics.
package server

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"lastgasp/internal/wire"
)

// Keyring maps host names to keys. The "*" entry is used for hosts without their own key.
type Keyring struct {
	hosts map[string][]byte
	def   []byte
}

// ParseKeyring reads lines of "host hexkey". Empty lines and lines starting with # are ignored.
func ParseKeyring(r io.Reader) (*Keyring, error) {
	k := &Keyring{hosts: map[string][]byte{}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("keys line %d: want \"host hexkey\"", n)
		}
		key, err := wire.ParseKey(f[1])
		if err != nil {
			return nil, fmt.Errorf("keys line %d: %w", n, err)
		}
		if f[0] == "*" {
			k.def = key
		} else {
			k.hosts[f[0]] = key
		}
	}
	// A file without keys is fine: agents can enroll instead.
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return k, nil
}

func LoadKeyring(path string) (*Keyring, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseKeyring(f)
}

// Lookup returns the key for host, or nil when the host is not allowed.
func (k *Keyring) Lookup(host string) []byte {
	if key, ok := k.hosts[host]; ok {
		return key
	}
	return k.def
}

// Exact returns the key of a host line, without the "*" entry.
func (k *Keyring) Exact(host string) []byte { return k.hosts[host] }

// Default returns the "*" key, or nil.
func (k *Keyring) Default() []byte { return k.def }

// KeyFile is a keyring loaded from a file that can be reloaded while the server runs.
type KeyFile struct {
	path string
	cur  atomic.Pointer[Keyring]
}

// OpenKeyFile loads the keyring at path.
func OpenKeyFile(path string) (*KeyFile, error) {
	k := &KeyFile{path: path}
	if err := k.Reload(); err != nil {
		return nil, err
	}
	return k, nil
}

// Reload reads the file again. On error the keys already loaded stay in use.
func (k *KeyFile) Reload() error {
	kr, err := LoadKeyring(k.path)
	if err != nil {
		return err
	}
	k.cur.Store(kr)
	return nil
}

// Lookup returns the key for host from the newest loaded keyring.
func (k *KeyFile) Lookup(host string) []byte { return k.cur.Load().Lookup(host) }

// Current returns the newest loaded keyring.
func (k *KeyFile) Current() *Keyring { return k.cur.Load() }

// Hosts returns the number of host entries, counting "*" as one.
func (k *KeyFile) Hosts() int {
	kr := k.cur.Load()
	n := len(kr.hosts)
	if kr.def != nil {
		n++
	}
	return n
}
