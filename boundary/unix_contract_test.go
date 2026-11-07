//go:build linux || darwin

package boundary

import (
	"context"
	"errors"
	"testing"
	"time"

	"eguard-nac-agent/collector"
)

// Every native Unix collector result, including the all-Unknown case on a host
// with none of the probed tools, must satisfy the service evidence contract.
// Otherwise the service collects forever and never sends posture.
func TestUnixCollectorOutputPassesBoundary(t *testing.T) {
	now := time.Now()
	none := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unavailable") }
	u := collector.UnixProvider{Root: t.TempDir(), Now: func() time.Time { return now }, Run: none}
	for name, p := range map[string]func() error{
		"linux": func() error { return ValidatePosture(u.LinuxPosture(context.Background(), ""), now) },
		"mac":   func() error { return ValidatePosture(u.MacPosture(context.Background(), ""), now) },
		"native": func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			return ValidatePosture(collector.CollectNative(ctx, ""), time.Now())
		},
	} {
		if err := p(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
