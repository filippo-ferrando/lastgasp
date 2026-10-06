package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"syscall"
	"time"
)

// Entry is one kernel log record.
type Entry struct {
	Priority uint16
	Seq      uint64
	TsUsec   uint64
	Msg      string
}

var errBadRecord = errors.New("kmsg: bad record")

// ParseKmsg parses one /dev/kmsg record: "prio,seq,usec,flags[,...];message\n[ KEY=value\n...]".
func ParseKmsg(b []byte) (Entry, error) {
	semi := bytes.IndexByte(b, ';')
	if semi < 0 {
		return Entry{}, errBadRecord
	}
	fields := bytes.SplitN(b[:semi], []byte(","), 5)
	if len(fields) < 3 {
		return Entry{}, errBadRecord
	}
	prio, err1 := strconv.ParseUint(string(fields[0]), 10, 16)
	seq, err2 := strconv.ParseUint(string(fields[1]), 10, 64)
	ts, err3 := strconv.ParseUint(string(fields[2]), 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return Entry{}, errBadRecord
	}
	msg := b[semi+1:]
	// Lines after the first newline are key=value metadata, not part of the message.
	if nl := bytes.IndexByte(msg, '\n'); nl >= 0 {
		msg = msg[:nl]
	}
	return Entry{Priority: uint16(prio), Seq: seq, TsUsec: ts, Msg: string(msg)}, nil
}

// recordSource returns one kmsg record per Read call, like /dev/kmsg does.
type recordSource interface {
	Read(p []byte) (int, error)
	Close() error
}

type fdSource int

func openKmsg(path string) (recordSource, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return fdSource(fd), nil
}

func (f fdSource) Read(p []byte) (int, error) {
	for {
		n, err := syscall.Read(int(f), p)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func (f fdSource) Close() error { return syscall.Close(int(f)) }

// KmsgReader reads the kernel log forever, reopening the device on errors.
type KmsgReader struct {
	Path    string
	OnEntry func(Entry)
	Stats   *Stats
	Log     *Logger
	open    func(string) (recordSource, error)
}

// Run blocks until ctx is done. A blocked read only returns when the kernel logs something new.
func (k *KmsgReader) Run(ctx context.Context) {
	open := k.open
	if open == nil {
		open = openKmsg
	}
	// Records are at most 8 KiB including metadata lines.
	buf := make([]byte, 16*1024)
	backoff := newBackoff(100*time.Millisecond, 5*time.Second)
	for ctx.Err() == nil {
		src, err := open(k.Path)
		if err != nil {
			k.Log.Printf("kmsg: open %s: %v", k.Path, err)
			backoff.Sleep(ctx)
			continue
		}
		k.readLoop(ctx, src, buf, backoff)
		src.Close()
	}
}

func (k *KmsgReader) readLoop(ctx context.Context, src recordSource, buf []byte, backoff *backoff) {
	for ctx.Err() == nil {
		n, err := src.Read(buf)
		switch {
		case err == nil:
			backoff.Reset()
			e, perr := ParseKmsg(buf[:n])
			if perr != nil {
				k.Stats.KmsgInvalid.Add(1)
				continue
			}
			k.Stats.KmsgRead.Add(1)
			k.OnEntry(e)
		case errors.Is(err, syscall.EPIPE):
			// The kernel overwrote records before they were read. Reading again continues with the oldest one left.
			k.Stats.KmsgOverruns.Add(1)
		case errors.Is(err, syscall.EAGAIN):
			backoff.Sleep(ctx)
		default:
			k.Log.Printf("kmsg: read: %v, reopening", err)
			backoff.Sleep(ctx)
			return
		}
	}
}
