package collector

import (
	"testing"
	"time"
)

func TestParseDMTF(t *testing.T) {
	got, ok := parseDMTF("20261105083000.000000+480")
	if !ok || !got.Equal(time.Date(2026, 11, 5, 0, 30, 0, 0, time.UTC)) {
		t.Fatalf("%v %v", got, ok)
	}
	for _, bad := range []string{"", "2026-11-05T00:00:00Z", "20261105083000.000000+999", "16010101000000.000000+000"} {
		if _, ok := parseDMTF(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}
