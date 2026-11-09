package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"eguard-nac-agent/core"
)

// These tests use mk's genuinely signed lifecycle.Accept/journal fixture, not
// unsigned expiry flags. The injected clock is a trusted-time fixture only.
func TestTemporaryCollectDeadlineCancelsCooperativeCollector(t *testing.T) {
	now := time.Unix(stamp+9, 0)
	var sends atomic.Int32
	var deadline time.Time
	c := mk(t, "temporary", "active", stamp+10, &now, func(ctx context.Context) (core.Posture, error) {
		var ok bool
		deadline, ok = ctx.Deadline()
		if !ok {
			t.Error("collector has no deadline")
		}
		<-ctx.Done()
		return core.Posture{}, ctx.Err()
	}, func(context.Context, core.Posture) error { sends.Add(1); return nil })
	c.CollectTimeout = 5 * time.Second
	c.SendTimeout = 5 * time.Second
	start := time.Now()
	state, e := c.Tick(context.Background())
	if state != Expired || !errors.Is(e, context.DeadlineExceeded) || sends.Load() != 0 || time.Since(start) > 2*time.Second || deadline.Sub(start) > 1500*time.Millisecond {
		t.Fatalf("collect deadline state=%s err=%v sends=%d bound=%v", state, e, sends.Load(), deadline.Sub(start))
	}
}
func TestTemporarySendDeadlineCancelsCooperativeSenderWithoutRewritingEvidence(t *testing.T) {
	now := time.Unix(stamp+9, 0)
	original := now.Add(-time.Second)
	var entered atomic.Bool
	var got time.Time
	c := mk(t, "temporary", "active", stamp+10, &now, func(context.Context) (core.Posture, error) { return evidence(original), nil }, func(ctx context.Context, p core.Posture) error {
		entered.Store(true)
		got = p.ObservedAt
		if _, ok := ctx.Deadline(); !ok {
			t.Error("sender has no deadline")
		}
		<-ctx.Done()
		return ctx.Err()
	})
	c.CollectTimeout = 5 * time.Second
	c.SendTimeout = 5 * time.Second
	start := time.Now()
	state, e := c.Tick(context.Background())
	if !entered.Load() || state != Expired || !errors.Is(e, context.DeadlineExceeded) || time.Since(start) > 2*time.Second || !got.Equal(original) {
		t.Fatalf("send deadline state=%s err=%v observation=%v", state, e, got)
	}
	// Even if the injected trusted clock fixture has not advanced, no subsequent
	// collection starts once the real expiry budget has been exhausted in this Tick.
}
func TestPermanentAndParentCancellationBoundDependencies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parent bool
	}{{"permanent cap", false}, {"parent cancel", true}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(stamp+100000, 0)
			var sends atomic.Int32
			c := mk(t, "permanent", "active", 0, &now, func(ctx context.Context) (core.Posture, error) { <-ctx.Done(); return core.Posture{}, ctx.Err() }, func(context.Context, core.Posture) error { sends.Add(1); return nil })
			c.CollectTimeout = 30 * time.Millisecond
			c.SendTimeout = 30 * time.Millisecond
			ctx := context.Background()
			if tc.parent {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				time.AfterFunc(5*time.Millisecond, cancel)
				defer cancel()
			}
			start := time.Now()
			state, e := c.Tick(ctx)
			if state != Stale || e == nil || sends.Load() != 0 || time.Since(start) > time.Second {
				t.Fatalf("unbounded collect: state=%s err=%v", state, e)
			}
			if tc.parent && !errors.Is(e, context.Canceled) {
				t.Fatalf("parent cancellation lost: %v", e)
			}
			if !tc.parent && !errors.Is(e, context.DeadlineExceeded) {
				t.Fatalf("permanent timeout lost: %v", e)
			}
		})
	}
}
func TestPermanentSendTimeoutAndMissingBoundsFailClosed(t *testing.T) {
	now := time.Unix(stamp+100000, 0)
	var calls atomic.Int32
	c := mk(t, "permanent", "active", 0, &now, func(context.Context) (core.Posture, error) { calls.Add(1); return evidence(now), nil }, func(ctx context.Context, p core.Posture) error { calls.Add(10); <-ctx.Done(); return ctx.Err() })
	c.CollectTimeout = 30 * time.Millisecond
	c.SendTimeout = 30 * time.Millisecond
	state, e := c.Tick(context.Background())
	if state != Outage || !errors.Is(e, context.DeadlineExceeded) || calls.Load() != 11 {
		t.Fatalf("permanent send cap: %s %v %d", state, e, calls.Load())
	}
	c.CollectTimeout = 0
	state, e = c.Tick(context.Background())
	if state != RecoveryRequired || e == nil || calls.Load() != 11 {
		t.Fatalf("unbounded config dispatched: %s %v", state, e)
	}
}
