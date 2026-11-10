package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PstoreLine is one line saved by the kernel in pstore before the last reboot.
type PstoreLine struct {
	FileID uint64
	Line   uint64
	// Part and Parts are set for records the agent saved to pmsg, which were already split. 0 otherwise.
	Part, Parts uint8
	Entry
}

// defaultPriority is used for lines without a "<N>" prefix (kern.info).
const defaultPriority = 6

// pstoreFile reports whether a pstore file holds text log lines. Compressed EFI records (.enc.z) are binary.
func pstoreFile(name string) bool {
	if strings.HasSuffix(name, ".enc.z") {
		return false
	}
	for _, p := range []string{"dmesg-", "console-", "pmsg-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ReadPstore reads all log files in dir. Files bigger than maxSize are cut at maxSize.
func ReadPstore(dir string, maxSize int64) ([]PstoreLine, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	var out []PstoreLine
	for _, e := range ents {
		if !e.Type().IsRegular() || !pstoreFile(e.Name()) {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxSize))
		f.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		out = append(out, ParsePstore(data)...)
	}
	return out, nil
}

// FileID fingerprints a pstore file by content, so the same file sent after many reboots keeps its ID.
func FileID(data []byte) uint64 {
	sum := sha256.Sum256(data)
	return binary.BigEndian.Uint64(sum[:8])
}

// ParsePstore splits a pstore file into lines like "<6>[    1.234567] message".
// The kernel repeats the prefix on each line of a multi-line record, so such lines are joined back
// and escaped like /dev/kmsg does, which lets the server match them with the kmsg copy.
func ParsePstore(data []byte) []PstoreLine {
	id := FileID(data)
	var out []PstoreLine
	kernel := []bool{} // whether out[n] has the "<N>[ts]" prefix of a kernel record
	prev := -2         // file line number of the last line added to out
	for i, raw := range bytes.Split(data, []byte("\n")) {
		line := strings.TrimRight(string(raw), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if e, part, parts, ok := parsePmsg(line); ok {
			out = append(out, PstoreLine{FileID: id, Line: uint64(i), Part: part, Parts: parts, Entry: e})
			kernel = append(kernel, false)
			prev = i
			continue
		}
		e, ok := parsePstoreLine(line)
		n := len(out) - 1
		if ok && prev == i-1 && kernel[n] && out[n].Priority == e.Priority && out[n].TsUsec == e.TsUsec {
			out[n].Msg += "\n" + e.Msg
		} else {
			out = append(out, PstoreLine{FileID: id, Line: uint64(i), Entry: e})
			kernel = append(kernel, ok)
		}
		prev = i
	}
	for n := range out {
		if kernel[n] {
			out[n].Msg = escapeKmsg(out[n].Msg)
		}
	}
	return out
}

// escapeKmsg writes control bytes, bytes above 126 and backslashes as \xNN, as /dev/kmsg shows them.
func escapeKmsg(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' || c >= 127 || c == '\\' {
			fmt.Fprintf(&b, "\\x%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// parsePstoreLine reads the optional "<N>" and "[ts]" prefixes. ok tells that both were there.
func parsePstoreLine(line string) (e Entry, ok bool) {
	e = Entry{Priority: defaultPriority, Msg: line}
	rest := line
	hasPrio := false
	if strings.HasPrefix(rest, "<") {
		if end := strings.IndexByte(rest, '>'); end > 1 {
			if p, err := strconv.ParseUint(rest[1:end], 10, 16); err == nil {
				e.Priority = uint16(p)
				rest = rest[end+1:]
				hasPrio = true
			}
		}
	}
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 0 {
			if ts, tsOK := parseTimestamp(rest[1:end]); tsOK {
				e.TsUsec = ts
				rest = strings.TrimPrefix(rest[end+1:], " ")
				ok = hasPrio
			}
		}
	}
	e.Msg = rest
	return e, ok
}

// parseTimestamp reads "   12.345678" as microseconds.
func parseTimestamp(s string) (uint64, bool) {
	sec, frac, ok := strings.Cut(strings.TrimSpace(s), ".")
	if !ok || len(frac) == 0 || len(frac) > 6 {
		return 0, false
	}
	frac += strings.Repeat("0", 6-len(frac))
	a, err1 := strconv.ParseUint(sec, 10, 64)
	b, err2 := strconv.ParseUint(frac, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return a*1_000_000 + b, true
}
