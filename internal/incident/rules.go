// Package incident finds crashes, reboots, silent hosts and kernel errors in stored logs and sends alerts.
package incident

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"lastgasp/internal/store"
)

// Rule marks kernel lines that point to a problem. A critical match in the last lines of a boot means a crash.
type Rule struct {
	Name     string
	Severity store.Severity
	Re       *regexp.Regexp
}

// Rules is an ordered list of rules. The first match wins.
type Rules struct{ list []Rule }

// Match returns the first rule matching msg, or nil.
func (r *Rules) Match(msg string) *Rule {
	if r == nil {
		return nil
	}
	for i := range r.list {
		if r.list[i].Re.MatchString(msg) {
			return &r.list[i]
		}
	}
	return nil
}

// Names lists the rule names in order.
func (r *Rules) Names() []string {
	out := make([]string, len(r.list))
	for i, x := range r.list {
		out[i] = x.Name
	}
	return out
}

var defaultRules = []struct{ name, sev, re string }{
	{"panic", "critical", `Kernel panic - not syncing`},
	{"lockup", "critical", `soft lockup - CPU#|Watchdog detected hard LOCKUP`},
	{"oops", "critical", `^Oops: |\bOops\b.*\[#\d+\]`},
	{"bug", "critical", `^BUG: `},
	{"gpf", "critical", `general protection fault`},
	{"mce", "critical", `\[Hardware Error\]`},
	{"memory_failure", "critical", `Memory failure: `},
	{"rcu_stall", "warning", `rcu_\w+ (self-)?detected stall|detected stalls on CPUs`},
	{"hung_task", "warning", `blocked for more than \d+ seconds`},
	{"oom", "warning", `Out of memory: Killed process`},
	{"io_error", "warning", `I/O error, dev |Buffer I/O error`},
	{"fs_error", "warning", `EXT4-fs error|XFS \(.*\): (Corruption|metadata I/O error)|BTRFS (error|critical)`},
	{"nvme", "warning", `nvme\w*: I/O \d+ .*timeout|nvme\w*: controller is down`},
}

// DefaultRules returns the built-in rules.
func DefaultRules() *Rules {
	r, err := ParseRules(strings.NewReader(""))
	if err != nil {
		panic(err)
	}
	return r
}

// ParseRules reads "name severity regexp" lines on top of the built-in rules.
// A known name replaces that rule, "name off" removes it. Empty lines and # comments are ignored.
func ParseRules(rd io.Reader) (*Rules, error) {
	r := &Rules{}
	for _, d := range defaultRules {
		r.list = append(r.list, Rule{d.name, mustSeverity(d.sev), regexp.MustCompile(d.re)})
	}
	sc := bufio.NewScanner(rd)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		sev, pattern, _ := strings.Cut(rest, " ")
		pattern = strings.TrimSpace(pattern)
		idx := -1
		for i := range r.list {
			if r.list[i].Name == name {
				idx = i
			}
		}
		if sev == "off" && pattern == "" {
			if idx >= 0 {
				r.list = append(r.list[:idx], r.list[idx+1:]...)
			}
			continue
		}
		s, err := store.ParseSeverity(sev)
		if err != nil || pattern == "" {
			return nil, fmt.Errorf("rules line %d: want \"name severity regexp\" or \"name off\"", n)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("rules line %d: %w", n, err)
		}
		if idx >= 0 {
			r.list[idx] = Rule{name, s, re}
		} else {
			r.list = append(r.list, Rule{name, s, re})
		}
	}
	return r, sc.Err()
}

// LoadRules reads a rules file. An empty path gives the built-in rules.
func LoadRules(path string) (*Rules, error) {
	if path == "" {
		return DefaultRules(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseRules(f)
}

func mustSeverity(name string) store.Severity {
	s, err := store.ParseSeverity(name)
	if err != nil {
		panic(err)
	}
	return s
}
