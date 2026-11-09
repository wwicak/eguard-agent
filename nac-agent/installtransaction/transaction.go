// Package installtransaction supplies a post-admission, mechanical SCM transaction.
// It does not authorize installation, provision credentials, or establish readiness by itself.
package installtransaction

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const ServiceName = "eGuardNAC"
const BinaryPath = `C:\Program Files\eGuard NAC\eguard-nac-service.exe`

var ErrExisting = errors.New("existing service: adoption/upgrade requires destructive restore and is unsupported")
var ErrPrerequisite = errors.New("missing operational readiness prerequisite")

// ErrServiceExited: SCM reported Stopped after a successful StartService, i.e. the
// service process terminated (SCM moves a started service to StartPending at minimum).
var ErrServiceExited = errors.New("service exited after start")

type State uint8

const (
	Missing State = iota
	Stopped
	Pending
	Running
)

type Snapshot struct {
	State  State
	Binary string
}

// Adapter must return create-owned=true ONLY after SCM confirms that this invocation
// created the fixed service. A failed create may still return true if creation succeeded
// but post-create inspection failed. Delete must verify exact configuration again.
type Adapter interface {
	Lookup(context.Context) (Snapshot, error)
	Create(context.Context) (created bool, err error)
	Start(context.Context) error
	Stop(context.Context) error
	Delete(context.Context) error
	// Ready must supply independent operational evidence; SCM Running alone is insufficient.
	Ready(context.Context) error
}

// The caller MUST have completed security admission and provisioning before invocation.
// SCM's production Ready deliberately fails closed until an authenticated operational
// readback is wired; a Windows Running status alone cannot satisfy this transaction.
func Run(ctx context.Context, a Adapter, interval time.Duration) (err error) {
	if ctx == nil || a == nil || interval <= 0 {
		return ErrPrerequisite
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	s, e := a.Lookup(ctx)
	if e != nil {
		return e
	}
	if s.State != Missing {
		return ErrExisting
	}
	created, e := a.Create(ctx)
	if created {
		defer func() {
			if err != nil {
				rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err = errors.Join(err, rollback(rctx, a, interval))
			}
		}()
	}
	if e != nil {
		return e
	}
	if !created {
		return errors.New("SCM create lacks ownership evidence")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = a.Start(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		var snap Snapshot
		snap, err = a.Lookup(ctx)
		if err != nil {
			return err
		}
		if snap.Binary != BinaryPath || snap.State == Missing {
			return ErrExisting
		}
		if snap.State == Stopped {
			return ErrServiceExited
		}
		if snap.State == Running {
			if err = a.Ready(ctx); err == nil {
				return nil
			}
			return fmt.Errorf("readiness: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
