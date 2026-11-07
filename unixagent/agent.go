//go:build linux || darwin

package unixagent

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"eguard-nac-agent/admission"
	"eguard-nac-agent/bootstrap"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/selfenroll"
	"eguard-nac-agent/servicefactory"
	"eguard-nac-agent/uninstall"
)

func Enroll(root, server, fp, code string, run Runner) (err error) {
	if selfenroll.ValidateServer(server) != nil || selfenroll.ValidateFingerprint(fp) != nil {
		return errors.New("invalid server or fingerprint")
	}
	if _, e := selfenroll.Normalize(code); e != nil {
		return e
	}
	id, e := selfenroll.FetchIdentity(context.Background(), server, fp)
	if e != nil {
		return e
	}
	// Exclusive creation is the transaction ownership proof. Never remove an
	// existing enrollment, even when it is incomplete or invalid.
	if e = os.Mkdir(root, 0700); e != nil {
		return fmt.Errorf("already enrolled or provisioning directory unavailable: %w", e)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(root))
		}
	}()
	csr, e := createKey(root)
	if e != nil {
		return e
	}
	roots, e := id.Roots()
	if e != nil {
		return e
	}
	hostname, _ := os.Hostname()
	result, e := selfenroll.Redeem("https://"+server+"/v1/nac/enroll", roots, code, csr, selfenroll.CleanHostname(hostname), runtime.GOOS)
	if e != nil {
		return e
	}
	if e = provision.WriteIdentity(root, server, id, fp); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(root, "machine-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.CertificateDER}), 0600); e != nil {
		return e
	}
	if _, e = admission.Install(root, result.Bootstrap, result.Activation, time.Now()); e != nil {
		return e
	}
	if e = serviceCommand(run, "start"); e != nil {
		return errors.Join(e, serviceCommand(run, "stop"), serviceCommand(run, "disable"))
	}
	return nil
}

type removal struct {
	root string
	run  Runner
}

func (a removal) Config() (uninstall.Config, error) {
	in, e := provision.LoadConfig(a.root)
	if e != nil {
		return uninstall.Config{}, e
	}
	v, e := bootstrap.Verify(in.BootstrapBytes, in.BootstrapPin, in.State.Binding, in.State.DurableFloor, in.State.JournalPath)
	if e != nil {
		return uninstall.Config{}, e
	}
	if e = provision.CheckEnrollmentTrust(a.root, v); e != nil {
		return uninstall.Config{}, e
	}
	return uninstall.Config{AntiTamper: v.AntiTamper(), Keys: v.LifecycleKeys(), Binding: v.Binding(), MachineCert: v.MachineCertSHA256()}, nil
}
func (a removal) StopService() error { return serviceCommand(a.run, "stop") }
func (a removal) Cleanup(_ [32]byte) error {
	return cleanupUnix(runtime.GOOS, productionCleanupPaths(a.root), a.run)
}
func (a removal) Handoff(raw []byte) error {
	p := filepath.Join(a.root, servicefactory.RequestFile)
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	for i := 0; i < 100; i++ {
		if _, e = os.Lstat(a.root); os.IsNotExist(e) {
			return nil
		}
		if raw, e := os.ReadFile(filepath.Join(a.root, servicefactory.ResultFile)); e == nil {
			return fmt.Errorf("uninstall result: %s", raw)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("uninstall authorization handed off; service did not confirm cleanup")
}
func Remove(root string, auth []byte, run Runner) error {
	return uninstall.Run(removal{root, run}, auth, time.Now())
}
func TerminalCleanup(root string, run Runner) error {
	// Called only after the verified runner has closed journal and credential.
	return cleanupUnix(runtime.GOOS, productionCleanupPaths(root), run)
}
