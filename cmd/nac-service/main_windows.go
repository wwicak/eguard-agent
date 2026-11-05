package main

import (
	"context"
	"eguard-nac-agent/boundary"
	"eguard-nac-agent/cleanup"
	"eguard-nac-agent/cngcred"
	"eguard-nac-agent/collector"
	"eguard-nac-agent/core"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/servicefactory"
	"eguard-nac-agent/servicehost"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"os"
	"time"
)

// verifiedRunnerFactory reads only the ACL-checked provisioning root, verifies the
// signed bootstrap with the build-time pin and the signed lifecycle journal, and
// resolves the non-exportable CNG machine credential. Any failure stops before
// Running without collecting or sending.
//
// Clock: system wallclock, guarded by bootintegration's in-process rollback latch
// and credential-validity checks. It is NOT a hardware/durable trusted clock.
const installDir = `C:\Program Files\eGuard NAC`

var verifiedRunnerFactory servicehost.Factory = func() (servicehost.Runner, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return servicefactory.New(servicefactory.Deps{
		Root:              provision.Root,
		ResolveCredential: cngcred.Resolve,
		Now:               func() (time.Time, error) { return time.Now(), nil },
		// Collection runs in the fixed-verb child under a kill-on-close Job Object.
		Collect: func(ctx context.Context) (core.Posture, error) { return boundary.Collect(ctx, self) },
		CollectInventory: func(ctx context.Context, software, user bool) (core.Inventory, error) {
			return boundary.CollectInventory(ctx, self, software, user)
		},
		// Official cleanup on signed Temporary expiry or accepted signed uninstall
		// authorization. Fixed NAC resources only; never EDR/OS/other apps.
		OnTerminal: func(state string, fp [32]byte) error {
			return cleanup.Run(cleanup.Windows{ServiceName: "eGuardNAC", ProvisioningRoot: provision.Root, InstallDir: installDir}, fp)
		},
	})()
}

type service struct{}

func (service) Execute(_ []string, changes <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	commands := make(chan servicehost.Command, 1)
	// Forward SCM commands to the host. Stop forwarding when host returns;
	// this goroutine cannot be abandoned on the configuration-required path.
	forwardCtx, stopForward := context.WithCancel(context.Background())
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		for {
			select {
			case <-forwardCtx.Done():
				return
			case change, ok := <-changes:
				if !ok {
					return
				}
				switch change.Cmd {
				case svc.Stop, svc.Shutdown:
					select {
					case commands <- servicehost.Stop:
					case <-forwardCtx.Done():
						return
					}
				case svc.Interrogate: // svc.Run manages SCM status; no collection occurs here.
				}
			}
		}
	}()
	err := servicehost.Run(verifiedRunnerFactory, commands, func(s servicehost.Status) {
		switch s {
		case servicehost.StartPending:
			status <- svc.Status{State: svc.StartPending}
		case servicehost.Running:
			status <- svc.Status{State: svc.Running, Accepts: accepts}
		case servicehost.StopPending:
			status <- svc.Status{State: svc.StopPending, WaitHint: 2000}
		}
	})
	stopForward()
	<-forwarded
	logOutcome(err)
	if errors.Is(err, servicefactory.ErrTerminal) {
		// Official cleanup ran (service marked for deletion). Report a clean stop.
		return false, 0
	}
	if err != nil {
		return true, 1
	} // SERVICE_SPECIFIC_ERROR, configuration required or runner failure.
	return false, 0
}

// logOutcome writes a single non-sensitive line to the Application event log.
func logOutcome(err error) {
	l, e := eventlog.Open("eGuardNAC")
	if e != nil {
		return
	}
	defer l.Close()
	switch {
	case err == nil:
		_ = l.Info(1, "eGuard NAC stopped.")
	case errors.Is(err, servicefactory.ErrTerminal):
		_ = l.Info(2, "eGuard NAC lifecycle ended; official cleanup result: "+err.Error())
	default:
		_ = l.Error(3, "eGuard NAC stopped: "+err.Error())
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--nac-fixed-collect" {
		if boundary.AwaitGate(os.Stdin, boundary.GateTimeout) != nil {
			os.Exit(2)
		}
		p := collector.CollectNative(context.Background(), "")
		if err := json.NewEncoder(os.Stdout).Encode(p); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == boundary.InventoryVerb && (os.Args[2] == "on" || os.Args[2] == "off") && (os.Args[3] == "on" || os.Args[3] == "off") {
		if boundary.AwaitGate(os.Stdin, boundary.GateTimeout) != nil {
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		inv := collector.CollectInventory(ctx, os.Args[2] == "on", os.Args[3] == "on")
		cancel()
		if err := json.NewEncoder(os.Stdout).Encode(inv); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	if err := svc.Run("eGuardNAC", service{}); err != nil {
		fmt.Fprintln(os.Stderr, "NAC service unavailable:", err)
		os.Exit(1)
	}
}
