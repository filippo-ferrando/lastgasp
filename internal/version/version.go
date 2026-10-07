// Package version holds the build version of the binaries.
package version

import "runtime/debug"

// Version is set at build time with -ldflags "-X lastgasp/internal/version.Version=v1.2.3".
var Version = "dev"

// String returns Version, or "dev" plus the commit when the build has no version.
func String() string {
	if Version != "dev" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		return Version
	}
	if dirty {
		rev += "-dirty"
	}
	return Version + "-" + rev
}
