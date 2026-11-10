package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"lastgasp/internal/wire"
)

// pmsgTag starts the lines the agent writes to pmsg, so they are told apart from other writers.
const pmsgTag = "LGPM1 "

// formatPmsg writes a kmsg item as one pmsg line: "LGPM1 prio ts seq part/parts message".
func formatPmsg(it Item) string {
	r := it.Rec
	return fmt.Sprintf("%s%d %d %d %d/%d %s\n", pmsgTag, r.Priority, r.TsUsec, r.Seq, r.Part, r.Parts, r.Msg)
}

// parsePmsg reads a line written by formatPmsg. The message keeps the kmsg escapes, so it has no newline.
func parsePmsg(line string) (e Entry, part, parts uint8, ok bool) {
	rest, ok := strings.CutPrefix(line, pmsgTag)
	if !ok {
		return e, 0, 0, false
	}
	f := strings.SplitN(rest, " ", 5)
	if len(f) < 4 {
		return e, 0, 0, false
	}
	prio, err1 := strconv.ParseUint(f[0], 10, 16)
	ts, err2 := strconv.ParseUint(f[1], 10, 64)
	seq, err3 := strconv.ParseUint(f[2], 10, 64)
	a, b, _ := strings.Cut(f[3], "/")
	p, err4 := strconv.ParseUint(a, 10, 8)
	n, err5 := strconv.ParseUint(b, 10, 8)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || p < 1 || p > n {
		return e, 0, 0, false
	}
	if len(f) == 5 {
		e.Msg = f[4]
	}
	e.Priority, e.TsUsec, e.Seq = uint16(prio), ts, seq
	return e, uint8(p), uint8(n), true
}

// SavePmsg writes the kmsg items to the pmsg device, newest kept within max bytes, oldest written first.
// The kernel keeps pmsg across a warm reboot, and the next boot sends the lines from pstore.
func SavePmsg(path string, items []Item, max int) (int, error) {
	var lines []string
	size := 0
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].Kind != wire.KindKmsg {
			continue
		}
		l := formatPmsg(items[i])
		if size+len(l) > max {
			break
		}
		size += len(l)
		lines = append(lines, l)
	}
	if len(lines) == 0 {
		return 0, nil
	}
	// No O_CREAT: on a kernel without pmsg the path must not become a regular file.
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	for i := len(lines) - 1; i >= 0; i-- {
		if _, err := f.WriteString(lines[i]); err != nil {
			return len(lines) - 1 - i, err
		}
	}
	return len(lines), nil
}
