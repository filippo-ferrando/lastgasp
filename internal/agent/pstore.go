package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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
	Entry
}

// defaultPriority is used for lines without a "<N>" prefix (kern.info).
const defaultPriority = 6

// pstoreFile reports whether a pstore file holds text log lines.
func pstoreFile(name string) bool {
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
func ParsePstore(data []byte) []PstoreLine {
	id := FileID(data)
	var out []PstoreLine
	for i, raw := range bytes.Split(data, []byte("\n")) {
		line := strings.TrimRight(string(raw), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		e := parsePstoreLine(line)
		out = append(out, PstoreLine{FileID: id, Line: uint64(i), Entry: e})
	}
	return out
}

func parsePstoreLine(line string) Entry {
	e := Entry{Priority: defaultPriority, Msg: line}
	rest := line
	if strings.HasPrefix(rest, "<") {
		if end := strings.IndexByte(rest, '>'); end > 1 {
			if p, err := strconv.ParseUint(rest[1:end], 10, 16); err == nil {
				e.Priority = uint16(p)
				rest = rest[end+1:]
			}
		}
	}
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 0 {
			if ts, ok := parseTimestamp(rest[1:end]); ok {
				e.TsUsec = ts
				rest = strings.TrimPrefix(rest[end+1:], " ")
			}
		}
	}
	e.Msg = rest
	return e
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
