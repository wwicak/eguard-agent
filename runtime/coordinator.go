// Package runtime is an unwired, platform-independent posture orchestration prerequisite.
// It neither installs services nor performs cleanup, enforcement, or enrollment.
package runtime

import (
	"context"
	"crypto/ed25519"
	"eguard-nac-agent/core"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"
)

type State string

const (
	Pending          State = "pending"
	Active           State = "active"
	Revoked          State = "revoked"
	Expired          State = "expired"
	Stale            State = "stale"
	Outage           State = "outage"
	Busy             State = "busy"
	CleanupIntent    State = "cleanup_intent"
	RecoveryRequired State = "recovery_required"
)

var ErrUnavailable = errors.New("runtime prerequisite unavailable")

// TerminalError ends Run when signed state means this installation must stop
// reporting and start official cleanup: Temporary expiry or an accepted signed
// uninstall authorization. Revoked/Pending are not cleanup permission.
type TerminalError struct{ State State }

func (e *TerminalError) Error() string { return "NAC lifecycle terminal: " + string(e.State) }

// Coordinator dependencies must be stable during Tick/Run. Now must be a trusted
// time estimate; raw local wallclock is NOT evidence of authorization.
type Coordinator struct {
	Store                                          *journal.Store
	Keys                                           map[string]ed25519.PublicKey
	Binding                                        lifecycle.Binding
	Now                                            func() (time.Time, error)
	Collect                                        func(context.Context) (core.Posture, error)
	Send                                           func(context.Context, core.Posture) error
	Interval, Backoff, CollectTimeout, SendTimeout time.Duration
	running                                        atomic.Bool
}

// authorized re-verifies committed history and signed expiry. remaining is
// duration derived ONLY from trusted Now and signed session expiry, never from
// converting server epoch into a local context absolute deadline.
func (c *Coordinator) authorized(now time.Time) (State, time.Duration, error) {
	if c.Store == nil || len(c.Keys) == 0 {
		return RecoveryRequired, 0, ErrUnavailable
	}
	obs, e := lifecycle.Recover(c.Store, c.Keys, c.Binding)
	if e != nil {
		return RecoveryRequired, 0, e
	}
	switch obs.State {
	case "pending":
		return Pending, 0, nil
	case "revoked":
		return Revoked, 0, nil
	case "cleanup_pending", "cleanup_done":
		return CleanupIntent, 0, nil
	case "active":
	default:
		return RecoveryRequired, 0, ErrUnavailable
	}
	p, e := c.Store.Read()
	if e != nil {
		return RecoveryRequired, 0, e
	}
	if len(p.History) == 0 {
		return RecoveryRequired, 0, ErrUnavailable
	}
	g, e := lifecycle.VerifyEnvelope(p.Lifecycle.Envelope, c.Keys, c.Binding)
	if e != nil {
		return RecoveryRequired, 0, e
	}
	var signed struct {
		Mode    string `json:"mode"`
		Expires *int64 `json:"session_expires_at"`
	}
	if e = json.Unmarshal(g.Payload, &signed); e != nil || signed.Mode != obs.Mode {
		return RecoveryRequired, 0, ErrUnavailable
	}
	switch signed.Mode {
	case "permanent":
		if signed.Expires != nil {
			return RecoveryRequired, 0, ErrUnavailable
		}
		return Active, 0, nil
	case "temporary":
		if signed.Expires == nil {
			return RecoveryRequired, 0, ErrUnavailable
		}
		remaining := time.Unix(*signed.Expires, 0).Sub(now)
		if remaining <= 0 {
			return Expired, 0, nil
		}
		return Active, remaining, nil
	default:
		return RecoveryRequired, 0, ErrUnavailable
	}
}

// operationContext combines the parent context, configured maximum and signed
// Temporary remaining duration. A context timer uses elapsed time after creation.
// It only bounds cooperative dependencies; it does not kill a blocked provider.
func operationContext(parent context.Context, maximum, remaining time.Duration, temporary bool) (context.Context, context.CancelFunc) {
	if temporary && remaining < maximum {
		maximum = remaining
	}
	return context.WithTimeout(parent, maximum)
}

// Tick is single-flight. Re-check signed history/expiry after collecting and
// immediately before sending, without modifying evidence timestamps.
func (c *Coordinator) Tick(ctx context.Context) (State, error) {
	if c == nil || !c.running.CompareAndSwap(false, true) {
		return Busy, nil
	}
	defer c.running.Store(false)
	if ctx == nil || c.Now == nil || c.Collect == nil || c.Send == nil || c.CollectTimeout <= 0 || c.SendTimeout <= 0 {
		return RecoveryRequired, ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return RecoveryRequired, e
	}
	now, e := c.Now()
	if e != nil {
		return RecoveryRequired, e
	}
	state, remaining, e := c.authorized(now)
	if e != nil || state != Active {
		return state, e
	}
	// Anchor the signed remaining budget to monotonic elapsed time. A later
	// trusted-clock sample may be conservative, but cannot replenish this budget.
	started := time.Now()
	initialRemaining := remaining
	collectCtx, stopCollect := operationContext(ctx, c.CollectTimeout, remaining, remaining > 0)
	p, collectErr := c.Collect(collectCtx)
	ctxErr := collectCtx.Err()
	stopCollect()
	if ctxErr != nil {
		if e := ctx.Err(); e != nil {
			return Stale, e
		}
		if remaining > 0 && errors.Is(ctxErr, context.DeadlineExceeded) && remaining <= c.CollectTimeout {
			return Expired, ctxErr
		}
		return Stale, ctxErr
	}
	if collectErr != nil {
		return Stale, collectErr
	}
	if e = ctx.Err(); e != nil {
		return Stale, e
	}
	now, e = c.Now()
	if e != nil {
		return RecoveryRequired, e
	}
	state, remaining, e = c.authorized(now)
	if e != nil || state != Active {
		return state, e
	}
	if initialRemaining > 0 {
		budget := initialRemaining - time.Since(started)
		if budget <= 0 {
			return Expired, context.DeadlineExceeded
		}
		if remaining > budget {
			remaining = budget
		}
	}
	if !p.Fresh(now) {
		return Stale, ErrUnavailable
	}
	if e = ctx.Err(); e != nil {
		return Stale, e
	}
	sendCtx, stopSend := operationContext(ctx, c.SendTimeout, remaining, remaining > 0)
	sendErr := c.Send(sendCtx, p)
	ctxErr = sendCtx.Err()
	stopSend()
	if ctxErr != nil {
		if e := ctx.Err(); e != nil {
			return Outage, e
		}
		if remaining > 0 && errors.Is(ctxErr, context.DeadlineExceeded) && remaining <= c.SendTimeout {
			return Expired, ctxErr
		}
		return Outage, ctxErr
	}
	if sendErr != nil {
		return Outage, sendErr
	}
	if initialRemaining > 0 && time.Since(started) >= initialRemaining {
		return Expired, context.DeadlineExceeded
	}
	if e = ctx.Err(); e != nil {
		return Outage, e
	}
	return Active, nil
}

// Run performs serial ticks, with cancellation interrupting waits and forwarded
// context. No goroutine is abandoned and no automatic transport retry is issued.
func (c *Coordinator) Run(ctx context.Context) error {
	if c == nil || ctx == nil || c.Interval <= 0 || c.Backoff <= 0 {
		return ErrUnavailable
	}
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		state, e := c.Tick(ctx)
		if state == Expired || state == CleanupIntent {
			if ctx.Err() == nil {
				return &TerminalError{State: state}
			}
		}
		wait := c.Interval
		if e != nil {
			wait = c.Backoff
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
