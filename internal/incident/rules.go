// Package incident finds crashes, reboots, silent hosts and kernel errors in stored logs and sends alerts.
package incident

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"lastgasp/internal/store"
)

// Rule marks kernel lines that point to a problem. A critical match in the last lines of a boot means a crash.
// With Count above 1, an incident opens only after Count matches within Window, for errors that are fine once.
// A rule with Journal set matches userspace lines from journald instead of kernel lines.
type Rule struct {
	Name     string
	Severity store.Severity
	Re       *regexp.Regexp
	Count    int
	Window   time.Duration
	Journal  bool
}

// Rules is an ordered list of rules. The first match wins.
type Rules struct{ list []Rule }

// Match returns the first kernel rule matching msg, or nil.
func (r *Rules) Match(msg string) *Rule { return r.match(msg, false) }

// MatchJournal returns the first journal rule matching msg, or nil.
func (r *Rules) MatchJournal(msg string) *Rule { return r.match(msg, true) }

func (r *Rules) match(msg string, journal bool) *Rule {
	if r == nil {
		return nil
	}
	for i := range r.list {
		if r.list[i].Journal == journal && r.list[i].Re.MatchString(msg) {
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

var defaultRules = []struct{ name, sev, rate, re string }{
	{"panic", "critical", "", `Kernel panic - not syncing`},
	{"lockup", "critical", "", `soft lockup - CPU#|Watchdog detected hard LOCKUP`},
	{"oops", "critical", "", `^Oops: |\bOops\b.*\[#\d+\]`},
	{"bug", "critical", "", `^BUG: `},
	{"gpf", "critical", "", `general protection fault`},
	// Corrected memory errors happen on healthy machines too. Only a rising count points to a failing part.
	{"mce_corrected", "warning", "10/1h", `Machine check events logged|\[Hardware Error\]: (Corrected error|event severity: corrected)`},
	{"edac_ce", "warning", "10/1h", `EDAC \S+: \d+ CE `},
	{"edac_ue", "critical", "", `EDAC \S+: \d+ UE `},
	{"mce", "critical", "", `\[Hardware Error\]`},
	{"memory_failure", "critical", "", `Memory failure: `},
	{"rcu_stall", "warning", "", `rcu_\w+ (self-)?detected stall|detected stalls on CPUs`},
	{"hung_task", "warning", "", `blocked for more than \d+ seconds`},
	{"oom", "warning", "", `Out of memory: Killed process`},
	{"io_error", "warning", "", `I/O error, dev |Buffer I/O error`},
	{"fs_error", "warning", "", `EXT4-fs error|XFS \(.*\): (Corruption|metadata I/O error)|BTRFS (error|critical)`},
	{"nvme", "warning", "", `nvme\w*: I/O \d+ .*timeout|nvme\w*: controller is down`},
	// Userspace rules, for lines from journald. Messages start with the unit or program name.
	{"coredump", "warning", "@journal", `Process \d+ \(.*\) of user \d+ (dumped core|terminated abnormally)`},
	{"unit_failed", "warning", "@journal", `: Failed with result '`},
}

// DefaultRules returns the built-in rules.
func DefaultRules() *Rules {
	r, err := ParseRules(strings.NewReader(""))
	if err != nil {
		panic(err)
	}
	return r
}

// ParseRules reads "name severity [@journal] [count/window] regexp" lines on top of the built-in rules.
// A known name replaces that rule, "name off" removes it. Empty lines and # comments are ignored.
func ParseRules(rd io.Reader) (*Rules, error) {
	r := &Rules{}
	for _, d := range defaultRules {
		rule := Rule{Name: d.name, Severity: mustSeverity(d.sev), Re: regexp.MustCompile(d.re), Journal: d.rate == "@journal"}
		if d.rate != "" && !rule.Journal {
			rule.Count, rule.Window, _ = parseRate(d.rate)
		}
		r.list = append(r.list, rule)
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
			return nil, fmt.Errorf("rules line %d: want \"name severity [@journal] [count/window] regexp\" or \"name off\"", n)
		}
		rule := Rule{Name: name, Severity: s}
		if rest, ok := strings.CutPrefix(pattern, "@journal "); ok {
			rule.Journal, pattern = true, strings.TrimSpace(rest)
		}
		if first, rest, ok := strings.Cut(pattern, " "); ok && rateRe.MatchString(first) {
			if rule.Count, rule.Window, err = parseRate(first); err != nil {
				return nil, fmt.Errorf("rules line %d: %w", n, err)
			}
			pattern = strings.TrimSpace(rest)
		}
		if rule.Re, err = regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("rules line %d: %w", n, err)
		}
		if idx >= 0 {
			r.list[idx] = rule
		} else {
			r.list = append(r.list, rule)
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

// rateRe tells a rate from the start of a regexp, which may hold a slash too, as in "I/O error".
var rateRe = regexp.MustCompile(`^\d+/\d`)

// parseRate reads "count/window", such as "10/1h".
func parseRate(v string) (int, time.Duration, error) {
	c, w, _ := strings.Cut(v, "/")
	count, err1 := strconv.Atoi(c)
	window, err2 := time.ParseDuration(w)
	if err1 != nil || err2 != nil || count < 1 || window <= 0 {
		return 0, 0, fmt.Errorf("invalid rate %q, want count/window such as 10/1h", v)
	}
	return count, window, nil
}

func mustSeverity(name string) store.Severity {
	s, err := store.ParseSeverity(name)
	if err != nil {
		panic(err)
	}
	return s
}
