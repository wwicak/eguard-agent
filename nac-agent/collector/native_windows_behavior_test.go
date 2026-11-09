//go:build windows

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"testing"
	"time"
)

func TestNativeDeadlineFailClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := CollectNative(ctx, "")
	if p.TTL != 0 || p.Domain.Result() != core.Unknown || p.AV.Result() != core.Unknown {
		t.Fatal("cancelled native collection fabricated fresh evidence")
	}
}
func TestNativeConcurrentDeadlineBound(t *testing.T) {
	// One request may still be executing slow WMI; a cancelled second request must not wait.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	start := time.Now()
	p := CollectNative(ctx, "")
	if time.Since(start) > time.Second || p.TTL != 0 {
		t.Fatal("native request did not fail closed promptly")
	}
}
