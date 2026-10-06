//go:build linux

package agent

import (
	"io"
	"syscall"
	"testing"
)

func TestLockAllFlags(t *testing.T) {
	defer func(f func(int) error) { mlockall = f }(mlockall)
	for _, c := range []struct {
		name      string
		unlimited bool
		onFault   error // answer of the kernel to MCL_ONFAULT
		want      []int
	}{
		{"on fault", true, nil, []int{syscall.MCL_CURRENT, syscall.MCL_FUTURE | mclOnFault}},
		{"old kernel", true, syscall.EINVAL, []int{syscall.MCL_CURRENT, syscall.MCL_FUTURE | mclOnFault, syscall.MCL_CURRENT | syscall.MCL_FUTURE}},
		{"fixed limit", false, nil, []int{syscall.MCL_CURRENT}},
	} {
		var got []int
		mlockall = func(flags int) error {
			got = append(got, flags)
			if flags&mclOnFault != 0 {
				return c.onFault
			}
			return nil
		}
		lockAll(NewLogger(io.Discard, 10), c.unlimited)
		if len(got) != len(c.want) {
			t.Fatalf("%s: calls %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: calls %v, want %v", c.name, got, c.want)
			}
		}
	}
}
