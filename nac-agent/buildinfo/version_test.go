package buildinfo

import "testing"

func TestDefaultVersion(t *testing.T) {
	if Version != "0.0.0-dev" {
		t.Fatalf("unstamped version %q", Version)
	}
}
