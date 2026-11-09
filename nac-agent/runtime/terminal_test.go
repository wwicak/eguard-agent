package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"eguard-nac-agent/core"
)

// Run must stop looping once signed state is terminal for this installation:
// Temporary expiry or an accepted signed uninstall authorization. It returns a
// TerminalError carrying the state so the service can start official cleanup.
// No collection/sending happens in that tick.
func TestRunReturnsTerminalOnExpiryAndCleanupIntent(t *testing.T) {
	for _, tc := range []struct {
		mode, action string
		expires      int64
		want         State
	}{{"temporary", "active", stamp + 5, Expired}, {"temporary", "authorize_uninstall", stamp + 60, CleanupIntent}} {
		t.Run(string(tc.want), func(t *testing.T) {
			now := time.Unix(stamp+20, 0)
			var calls atomic.Int32
			c := mk(t, tc.mode, tc.action, tc.expires, &now, func(context.Context) (core.Posture, error) { calls.Add(1); return evidence(now), nil }, func(context.Context, core.Posture) error { calls.Add(1); return nil })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			e := c.Run(ctx)
			var term *TerminalError
			if !errors.As(e, &term) || term.State != tc.want {
				t.Fatalf("Run=%v, want TerminalError{%s}", e, tc.want)
			}
			if calls.Load() != 0 {
				t.Fatalf("collected/sent after terminal state: %d", calls.Load())
			}
		})
	}
}

// Revoked and Pending are NOT cleanup permission: revoke removes access server-side
// but is not uninstall. Run keeps waiting (cancellable) and never collects.
func TestRunKeepsWaitingOnRevokedAndPending(t *testing.T) {
	for _, action := range []string{"revoke", "pending"} {
		t.Run(action, func(t *testing.T) {
			now := time.Unix(stamp+20, 0)
			var calls atomic.Int32
			c := mk(t, "temporary", action, stamp+60, &now, func(context.Context) (core.Posture, error) { calls.Add(1); return evidence(now), nil }, func(context.Context, core.Posture) error { calls.Add(1); return nil })
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			if e := c.Run(ctx); !errors.Is(e, context.DeadlineExceeded) {
				t.Fatalf("Run=%v", e)
			}
			if calls.Load() != 0 {
				t.Fatal("collected while not active")
			}
		})
	}
}

// Expiry reached while running (between ticks) must also end Run.
func TestRunEndsWhenTemporaryExpiresDuringOperation(t *testing.T) {
	now := time.Unix(stamp+2, 0)
	var ticks atomic.Int32
	c := mk(t, "temporary", "active", stamp+10, &now, func(context.Context) (core.Posture, error) {
		if ticks.Add(1) == 2 {
			now = time.Unix(stamp+11, 0)
		}
		return evidence(now), nil
	}, func(context.Context, core.Posture) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var term *TerminalError
	if e := c.Run(ctx); !errors.As(e, &term) || term.State != Expired {
		t.Fatalf("Run=%v", e)
	}
}
