package installtransaction

import (
	"context"
	"time"
)

// StabilityWindow is how long the service must stay Running after start to count
// as ready. servicehost reports Running only after the verified factory succeeded,
// and a failed factory/crash moves SCM to Stopped well inside this window.
const StabilityWindow = 10 * time.Second

// stableRunning polls until the service has been continuously Running with the
// fixed NAC binary for the whole window.
func stableRunning(ctx context.Context, lookup func(context.Context) (Snapshot, error), window, interval time.Duration) error {
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		s, e := lookup(ctx)
		if e != nil {
			return e
		}
		if s.Binary != BinaryPath || s.State == Missing {
			return ErrExisting
		}
		if s.State != Running {
			return ErrServiceExited
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return nil
		case <-ticker.C:
		}
	}
}
