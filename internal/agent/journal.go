package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"hash/fnv"
	"io"
	"os/exec"
	"strconv"
	"time"
)

// JournalReader follows journald through journalctl and passes userspace lines to Push.
// It runs apart from the kmsg reader, so a stuck journald only stops these lines.
type JournalReader struct {
	Command  string // journalctl, or another program printing the same JSON lines, for tests
	Priority int    // lines up to this level are read, 4 for warning
	Rate     int    // lines per second at most, the rest are dropped and counted
	Stats    *Stats
	Log      *Logger
	// Push queues one line. id is a hash of the journal cursor, so the server can drop repeated lines.
	Push func(e Entry, id uint64)

	cursor string // of the newest line passed on, to go on from there after journalctl exits
}

// Run follows the journal until ctx is done, starting journalctl again when it exits.
// The first run reads the whole boot, so lines from before the agent started are sent too.
func (j *JournalReader) Run(ctx context.Context) {
	retry := newBackoff(time.Second, time.Minute)
	for ctx.Err() == nil {
		start := time.Now()
		if err := j.follow(ctx); err != nil && ctx.Err() == nil {
			j.Log.Printf("journal: %v", err)
		}
		if time.Since(start) > time.Minute {
			retry.Reset()
		}
		retry.Sleep(ctx)
	}
}

func (j *JournalReader) follow(ctx context.Context) error {
	args := []string{"--follow", "--boot", "--lines=all", "--output=json", "--no-pager", "--priority=0.." + strconv.Itoa(j.Priority)}
	if j.cursor != "" {
		args = append(args, "--after-cursor="+j.cursor)
	}
	cmd := exec.CommandContext(ctx, j.Command, args...)
	setParentDeathSignal(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var second time.Time
	sent := 0
	for sc.Scan() {
		e, id, cursor, ok := parseJournal(sc.Bytes())
		if cursor != "" {
			j.cursor = cursor
		}
		if !ok {
			continue
		}
		if now := time.Now(); now.Sub(second) >= time.Second {
			second, sent = now, 0
		}
		if j.Rate > 0 && sent >= j.Rate {
			j.Stats.BufferDrops.Add(1)
			continue
		}
		sent++
		j.Push(e, id)
	}
	// Reading stops on a line over 1 MiB too, so the rest of the output must be thrown away for journalctl to exit.
	io.Copy(io.Discard, out)
	if err := sc.Err(); err != nil {
		return err
	}
	return cmd.Wait()
}

// parseJournal reads one line of "journalctl --output=json". Kernel lines are skipped, as kmsg sends them.
func parseJournal(b []byte) (e Entry, id uint64, cursor string, ok bool) {
	var f map[string]json.RawMessage
	if json.Unmarshal(b, &f) != nil {
		return e, 0, "", false
	}
	cursor = journalField(f["__CURSOR"])
	msg := journalField(f["MESSAGE"])
	if cursor == "" || msg == "" || journalField(f["_TRANSPORT"]) == "kernel" {
		return e, 0, cursor, false
	}
	prio, err := strconv.Atoi(journalField(f["PRIORITY"]))
	if err != nil || prio < 0 || prio > 7 {
		prio = 6
	}
	// Facility 3 is daemon, the default of syslog() for services.
	facility, err := strconv.Atoi(journalField(f["SYSLOG_FACILITY"]))
	if err != nil || facility < 0 || facility > 23 {
		facility = 3
	}
	// A user service is better named by its own unit than by user@UID.service.
	who := journalField(f["_SYSTEMD_USER_UNIT"])
	for _, k := range []string{"_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_COMM"} {
		if who == "" {
			who = journalField(f[k])
		}
	}
	if who != "" {
		msg = who + ": " + msg
	}
	ts, _ := strconv.ParseUint(journalField(f["__MONOTONIC_TIMESTAMP"]), 10, 64)
	h := fnv.New64a()
	h.Write([]byte(cursor))
	return Entry{Priority: uint16(facility<<3 | prio), TsUsec: ts, Msg: escapeKmsg(msg)}, h.Sum64(), cursor, true
}

// journalField reads a field written as a string, or as an array of bytes when it is not valid UTF-8.
func journalField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var bs []byte
	var nums []int
	if json.Unmarshal(raw, &nums) == nil {
		for _, n := range nums {
			bs = append(bs, byte(n))
		}
	}
	return string(bs)
}
