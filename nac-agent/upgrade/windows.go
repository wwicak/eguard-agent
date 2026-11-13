//go:build windows

package upgrade

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"eguard-nac-agent/installtransaction"
	"eguard-nac-agent/uninstall"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type Windows struct {
	Source    string
	Reinstall bool
	protected bool
	scm       *installtransaction.SCM
}

func binaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, path, "version").Output()
	return strings.TrimSpace(string(b)), e
}
func (w *Windows) Preflight() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator rights required")
	}
	fi, e := os.Stat(w.Source)
	if e != nil {
		return e
	}
	if !fi.Mode().IsRegular() {
		return errors.New("invalid binary")
	}
	oldfi, e := os.Stat(installtransaction.BinaryPath)
	if e != nil {
		return e
	}
	if os.SameFile(fi, oldfi) {
		return errors.New("source must differ from installed binary")
	}
	c, e := (uninstall.Windows{}).Config()
	if e != nil {
		return e
	}
	w.protected = c.AntiTamper == "on"
	// Query using minimum rights: ProtectedSDDL deliberately denies ALL_ACCESS.
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	h, e := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(installtransaction.ServiceName), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return e
	}
	s := &mgr.Service{Name: installtransaction.ServiceName, Handle: h}
	defer s.Close()
	if e = installtransaction.CheckUpgradeService(s); e != nil {
		return e
	}
	next, e := binaryVersion(w.Source)
	if e != nil {
		return errors.New("new binary has no readable version")
	}
	old, _ := binaryVersion(installtransaction.BinaryPath)
	return CheckVersion(old, next, w.Reinstall)
}

// Administrators can take ownership with the privileges enabled by nac-setup.
// Restore the original owner immediately; never change provisioning ACLs.
func serviceDACL(sddl string) (err error) {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	name := windows.StringToUTF16Ptr(installtransaction.ServiceName)
	h, e := windows.OpenService(m.Handle, name, windows.READ_CONTROL|windows.WRITE_OWNER)
	if e != nil {
		return e
	}
	defer windows.CloseServiceHandle(h)
	sd, e := windows.GetSecurityInfo(windows.Handle(h), windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return e
	}
	admin, e := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if e != nil {
		return e
	}
	if e = windows.SetSecurityInfo(windows.Handle(h), windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION, admin, nil, nil, nil); e != nil {
		return e
	}
	defer func() {
		err = errors.Join(err, windows.SetSecurityInfo(windows.Handle(h), windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil))
	}()
	return uninstall.SetServiceDACL(sddl)
}
func (w *Windows) Relax() error {
	if w.protected {
		if e := serviceDACL(uninstall.DefaultSDDL); e != nil {
			return e
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var e error
	w.scm, e = installtransaction.ExistingForUpgrade(ctx)
	return e
}
func (w *Windows) Protect() error {
	if w.protected {
		return serviceDACL(uninstall.ProtectedSDDL)
	}
	return nil
}
func (w *Windows) Stop() error { return (uninstall.Windows{}).StopService() }
func (w *Windows) Backup() error {
	// Retain the most recent previous binary; current binary is still intact here.
	if e := os.Remove(installtransaction.BinaryPath + ".prev"); e != nil && !os.IsNotExist(e) {
		return e
	}
	return os.Rename(installtransaction.BinaryPath, installtransaction.BinaryPath+".prev")
}
func (w *Windows) Replace() error {
	in, e := os.Open(w.Source)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(installtransaction.BinaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	return errors.Join(e, out.Close())
}
func (w *Windows) Restore() error {
	if e := os.Remove(installtransaction.BinaryPath); e != nil && !os.IsNotExist(e) {
		return e
	}
	return os.Rename(installtransaction.BinaryPath+".prev", installtransaction.BinaryPath)
}
func (w *Windows) StartReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Start may report already running after a failed stop/backup recovery.
	if e := w.scm.Start(ctx); e != nil && !errors.Is(e, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return e
	}
	for {
		snap, e := w.scm.Lookup(ctx)
		if e != nil {
			return e
		}
		switch snap.State {
		case installtransaction.Running:
			return w.scm.Ready(ctx)
		case installtransaction.Stopped, installtransaction.Missing:
			return installtransaction.ErrServiceExited
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
