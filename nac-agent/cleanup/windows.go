//go:build windows

package cleanup

import (
	"errors"
	"os"
	"path/filepath"

	"eguard-nac-agent/cngcred"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows is the production adapter. All paths/names are fixed NAC resources.
type Windows struct {
	ServiceName      string // "eGuardNAC"
	ProvisioningRoot string // provision.Root
	InstallDir       string // C:\Program Files\eGuard NAC
}

func (w Windows) MarkServiceForDeletion() error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	// Request only DELETE: the Anti-Tamper DACL grants SYSTEM delete but not
	// every right in SERVICE_ALL_ACCESS (which mgr.OpenService would ask for).
	name, e := windows.UTF16PtrFromString(w.ServiceName)
	if e != nil {
		return e
	}
	h, e := windows.OpenService(m.Handle, name, windows.DELETE)
	if errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if e != nil {
		return e
	}
	defer windows.CloseServiceHandle(h)
	e = windows.DeleteService(h)
	if errors.Is(e, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return nil
	}
	return e
}

func (w Windows) RemoveMachineCredential(fp [32]byte) error {
	if e := cngcred.Delete(fp); e != nil && !errors.Is(e, cngcred.ErrNotFound) {
		return e
	}
	return nil
}

func (w Windows) RemoveProvisioning() error {
	if w.ProvisioningRoot == "" || !filepath.IsAbs(w.ProvisioningRoot) {
		return errors.New("provisioning root not fixed")
	}
	e := os.RemoveAll(w.ProvisioningRoot)
	if e != nil {
		return e
	}
	return nil
}

// ScheduleBinaryRemoval deletes what it can now and schedules in-use files and the
// directory for deletion at next boot (MOVEFILE_DELAY_UNTIL_REBOOT). The service
// binary is in use while this runs from the service itself.
func (w Windows) ScheduleBinaryRemoval() error {
	if w.InstallDir == "" || !filepath.IsAbs(w.InstallDir) {
		return errors.New("install dir not fixed")
	}
	entries, e := os.ReadDir(w.InstallDir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var errs []error
	for _, ent := range entries {
		p := filepath.Join(w.InstallDir, ent.Name())
		if ent.IsDir() {
			// NAC installs no subdirectories; never recurse into unexpected content.
			errs = append(errs, errors.New("unexpected directory in install dir: "+ent.Name()))
			continue
		}
		if os.Remove(p) != nil {
			errs = append(errs, delayDelete(p))
		}
	}
	if os.Remove(w.InstallDir) != nil {
		errs = append(errs, delayDelete(w.InstallDir))
	}
	return errors.Join(errs...)
}

func delayDelete(p string) error {
	from, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(from, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
