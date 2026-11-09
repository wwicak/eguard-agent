package bootintegration

import (
	"context"
	"eguard-nac-agent/core"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSHandshakeCannotBypassClockRollbackGuard(t *testing.T) {
	r := newRig(t)
	r.createJournal(t)
	in := r.inputs()
	var calls atomic.Int32
	base := time.Now()
	in.Collect = func(context.Context) (core.Posture, error) {
		return core.Posture{AgentType: "nac", ObservedAt: base, TTL: time.Minute}, nil
	}
	// Build samples twice, runtime samples before/after collection, then TLS.
	in.Now = func() (time.Time, error) {
		if calls.Add(1) >= 5 {
			return base.Add(-time.Minute), nil
		}
		return base, nil
	}
	runner, closeFn, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = runner(ctx)
	if calls.Load() < 5 {
		t.Fatal("test did not reach TLS time check")
	}
	if r.received.Load() != 0 {
		t.Fatal("TLS rollback bypassed runtime guard")
	}
}
