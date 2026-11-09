// Package servicefactory wires the provisioned local store to the verified boot
// factory. It adds no trust of its own: every check lives in provision.Load,
// bootstrap.Verify (inside bootintegration.Build) and the lifecycle journal.
package servicefactory

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"time"

	"eguard-nac-agent/bootintegration"
	"eguard-nac-agent/bootstrap"
	"eguard-nac-agent/clockguard"
	"eguard-nac-agent/core"
	"eguard-nac-agent/provision"
	nacruntime "eguard-nac-agent/runtime"
	"eguard-nac-agent/servicehost"
)

// Deps are trusted installation-time dependencies, not user configuration.
type Deps struct {
	// Root is the provisioning root; production passes provision.Root.
	Root              string
	ResolveCredential func([32]byte) (tls.Certificate, io.Closer, error)
	Now               func() (time.Time, error)
	Collect           func(context.Context) (core.Posture, error)
	// CollectInventory: optional inventory collector (enabled by signed config).
	CollectInventory func(ctx context.Context, software, user bool) (core.Inventory, error)
	// OnTerminal performs official cleanup for a signed terminal state
	// (StateExpired / StateCleanupIntent) with the signed machine-cert fingerprint.
	// Optional; nil means stop without cleanup.
	OnTerminal func(state string, machineCert [32]byte) error
	// RequestPoll is how often the uninstall request hand-off is checked
	// (default 2s).
	RequestPoll time.Duration
}

var ErrDeps = errors.New("service factory dependencies missing")

// ClockFile holds the durable trusted-time high-water mark (clockguard).
const ClockFile = "clock.hw"

// New returns a servicehost.Factory. The runner releases journal and credential
// after the coordinator returns; a failed Build never collects or sends.
func New(d Deps) servicehost.Factory {
	return func() (servicehost.Runner, error) {
		if d.Root == "" || d.ResolveCredential == nil || d.Now == nil || d.Collect == nil {
			return nil, ErrDeps
		}
		in, err := provision.Load(d.Root)
		if err != nil {
			return nil, err
		}
		verified, verifyErr := bootstrap.Verify(in.BootstrapBytes, in.BootstrapPin, in.State.Binding, in.State.DurableFloor, in.State.JournalPath)
		if verifyErr != nil {
			return nil, verifyErr
		}
		if err = provision.CheckEnrollmentTrust(d.Root, verified); err != nil {
			return nil, err
		}
		clockPath := filepath.Join(d.Root, ClockFile)
		hw, err := clockguard.Load(clockPath)
		if err != nil {
			return nil, err
		}
		raw, err := d.Now()
		if err != nil {
			return nil, err
		}
		// Expiry is judged against max(clock, high-water): rolling the clock back
		// cannot reopen an expired session.
		now := clockguard.Effective(raw, hw)
		terminal := func(state string, fp [32]byte) error {
			if d.OnTerminal == nil {
				return ErrTerminal
			}
			return errors.Join(ErrTerminal, d.OnTerminal(state, fp))
		}
		// Signed terminal state takes precedence over normal startup and does not
		// depend on the machine credential or the server being reachable. This is
		// how expiry that passed while the device was off is cleaned up on boot.
		state, fp, err := terminalAtBoot(in, d.Root, now)
		if err != nil {
			return nil, err
		}
		if state != "" {
			return func(context.Context) error { return terminal(state, fp) }, nil
		}
		// Beyond terminal handling, a large rollback fails closed (no posture).
		if err := clockguard.Check(raw, hw); err != nil {
			return nil, err
		}
		// Every trusted sample used by the runtime raises the durable mark and is
		// itself checked against it.
		guardedNow := func() (time.Time, error) {
			t, e := d.Now()
			if e != nil {
				return t, e
			}
			cur, e := clockguard.Load(clockPath)
			if e != nil {
				return time.Time{}, e
			}
			if e := clockguard.Check(t, cur); e != nil {
				return time.Time{}, e
			}
			_ = clockguard.Raise(clockPath, t)
			return t, nil
		}
		// Same fixed file name provision.Load verified (ACL/reparse + binding).
		// Do not derive it with filepath.Base: on non-Windows builds the
		// Windows-separated constant would not split.
		journalDisk := filepath.Join(d.Root, "journal.db")
		remote := make(chan []byte, 1)
		runner, closeFn, err := bootintegration.Build(bootintegration.Inputs{
			RawConfig:    in.BootstrapBytes,
			BootstrapPin: in.BootstrapPin,
			Binding:      in.State.Binding,
			DurableFloor: in.State.DurableFloor,
			JournalPath:  in.State.JournalPath,
			// The signed config names the fixed production path; map it only to
			// the journal inside the already ACL-checked provisioning root.
			ResolveJournalPath: func(p string) (string, error) {
				if p != provision.JournalPath {
					return "", ErrDeps
				}
				return journalDisk, nil
			},
			ResolveCredential: d.ResolveCredential,
			Now:               guardedNow,
			Collect:           d.Collect,
			CollectInventory:  d.CollectInventory,
			OnLifecycle: func(g []byte) {
				select {
				case remote <- append([]byte(nil), g...):
				default: // one pending grant is enough; never block transport
				}
			},
		})
		if err != nil {
			return nil, err
		}
		v, err := bootstrap.Verify(in.BootstrapBytes, in.BootstrapPin, in.State.Binding, in.State.DurableFloor, in.State.JournalPath)
		if err != nil {
			_ = closeFn()
			return nil, err
		}
		keys, b := v.LifecycleKeys(), v.Binding()
		poll := d.RequestPoll
		if poll <= 0 {
			poll = 2 * time.Second
		}
		var once sync.Once
		return func(ctx context.Context) error {
			runCtx, stopRun := context.WithCancel(ctx)
			defer stopRun()
			reqCh := make(chan []byte, 1)
			go func() { reqCh <- watchRequests(runCtx, d.Root, poll, keys, b, d.Now, stopRun, remote) }()
			runErr := runner(runCtx)
			stopRun()
			req := <-reqCh
			var closeErr error
			once.Do(func() { closeErr = closeFn() })
			if req != nil && ctx.Err() == nil {
				// Journal is released; record the grant (replay/sequence checks).
				at, e := d.Now()
				if e == nil {
					e = acceptRequest(d.Root, req, keys, b, at)
				}
				if e != nil {
					writeResult(d.Root, "rejected: "+e.Error())
					return errors.Join(e, closeErr)
				}
				writeResult(d.Root, "accepted")
				return errors.Join(closeErr, terminal(StateCleanupIntent, fp))
			}
			var term *nacruntime.TerminalError
			if errors.As(runErr, &term) {
				name := StateExpired
				if term.State == nacruntime.CleanupIntent {
					name = StateCleanupIntent
				}
				// Credential and journal are closed before cleanup deletes them.
				return errors.Join(closeErr, terminal(name, fp))
			}
			return errors.Join(runErr, closeErr)
		}, nil
	}
}
