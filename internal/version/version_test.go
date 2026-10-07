package version

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "v1.2.3"
	if String() != "v1.2.3" {
		t.Fatalf("got %q", String())
	}
	Version = "dev"
	if !strings.HasPrefix(String(), "dev") {
		t.Fatalf("got %q", String())
	}
}
