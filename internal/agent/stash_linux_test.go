//go:build linux

package agent

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// shmDir returns a directory on tmpfs, or skips the test.
func shmDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/dev/shm", "lastgasp-test-")
	if err != nil {
		t.Skip("no /dev/shm:", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestOpenStashAcrossRuns(t *testing.T) {
	path := filepath.Join(shmDir(t), "sub", "agent.stash")
	log := NewLogger(io.Discard, 10)
	boot := [16]byte{9}
	s, got, err := OpenStash(path, MinStash, boot, log)
	if err != nil || len(got) != 0 {
		t.Fatalf("first open: %v %v", err, got)
	}
	q := NewQueue(10)
	q.Mirror(s, tagMain)
	q.Push(kmsgItem(1, "kept"))
	// No Close: the run ends as if killed. A bigger size still recovers the records.
	s2, got, err := OpenStash(path, 2*MinStash, boot, log)
	if err != nil || len(got) != 1 || got[0].Rec.Msg != "kept" {
		t.Fatalf("second open: %v %v", err, msgs(got))
	}
	if st, _ := os.Stat(path); st.Size() != stashHeader+2*MinStash {
		t.Fatalf("file size %d", st.Size())
	}
	// The stash starts empty after a recovery, the caller pushes the records again.
	if _, got, _ := OpenStash(path, 2*MinStash, boot, log); len(got) != 0 {
		t.Fatalf("third open: %v", msgs(got))
	}
	s.Close()
	s2.Close()
}

func TestOpenStashRefusesDisk(t *testing.T) {
	dir, _ := os.Getwd()
	var fs syscall.Statfs_t
	if syscall.Statfs(dir, &fs) != nil || uint32(fs.Type) == tmpfsMagic || uint32(fs.Type) == ramfsMagic {
		t.Skip("working directory is not on a disk")
	}
	if _, _, err := OpenStash(filepath.Join(dir, "never-created.stash"), MinStash, [16]byte{}, NewLogger(io.Discard, 10)); err == nil {
		t.Fatal("stash opened on a disk")
	}
	if _, err := os.Stat(filepath.Join(dir, "never-created.stash")); err == nil {
		t.Fatal("stash file written to a disk")
	}
}

func TestOpenStashRefusesSymlink(t *testing.T) {
	dir := shmDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.stash")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStash(path, MinStash, [16]byte{}, nil); err == nil {
		t.Fatal("stash followed a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("target changed: %q", b)
	}
}

func TestOpenStashRefusesNonRegular(t *testing.T) {
	path := filepath.Join(shmDir(t), "agent.stash")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStash(path, MinStash, [16]byte{}, nil); err == nil {
		t.Fatal("stash opened a fifo")
	}
}

func TestOpenStashSkipsBiggerFile(t *testing.T) {
	path := filepath.Join(shmDir(t), "agent.stash")
	boot := [16]byte{9}
	// A valid header with one entry as long as a 1 GiB ring, in a sparse file.
	hdr := make([]byte, stashHeader+4)
	copy(hdr, stashMagic)
	binary.LittleEndian.PutUint32(hdr[offVersion:], stashVersion)
	copy(hdr[offBoot:], boot[:])
	binary.LittleEndian.PutUint64(hdr[offRingSize:], MaxStash)
	binary.LittleEndian.PutUint64(hdr[offTail:], MaxStash)
	binary.LittleEndian.PutUint32(hdr[stashHeader:], MaxStash)
	if err := os.WriteFile(path, hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, stashHeader+MaxStash); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	s, got, err := OpenStash(path, MinStash, boot, nil)
	runtime.ReadMemStats(&after)
	if err != nil || len(got) != 0 {
		t.Fatalf("open: %v %v", err, msgs(got))
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 1<<20 {
		t.Fatalf("open allocated %d bytes", n)
	}
	defer s.Close()
	if st, _ := os.Stat(path); st.Size() != stashHeader+MinStash {
		t.Fatalf("file size %d", st.Size())
	}
}
