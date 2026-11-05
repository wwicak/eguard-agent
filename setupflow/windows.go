//go:build windows

package setupflow

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"eguard-nac-agent/admission"
	"eguard-nac-agent/installtransaction"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/uninstall"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"reflect"
)

const EventSource = "eGuardNAC"

// Windows performs the real steps. SourceBinary is the payload extracted by the
// installer; Bootstrap/Activation are the operator-supplied signed files.
type Windows struct {
	SourceBinary, Bootstrap, Activation string
	Now                                 func() time.Time
}

func (w Windows) Preflight() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator rights are required")
	}
	for _, p := range []string{w.SourceBinary, w.Bootstrap, w.Activation} {
		if fi, e := os.Stat(p); e != nil || !fi.Mode().IsRegular() {
			return errors.New("installer input missing: " + filepath.Base(p))
		}
	}
	if _, e := os.Lstat(provision.Root); e == nil {
		return errors.New("eGuard NAC is already provisioned on this device; uninstall first")
	}
	return CheckExisting()
}

// CheckExisting must run before spending an enrollment code or removing stale files.
func CheckExisting() error {
	if _, e := os.Lstat(provision.Root); e == nil {
		return errors.New("eGuard NAC is already provisioned on this device; uninstall first")
	} else if !os.IsNotExist(e) {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	// A protected (Anti-Tamper) service denies SERVICE_ALL_ACCESS to admins, so
	// "access denied" also means it exists. Only DOES_NOT_EXIST proceeds.
	s, e := m.OpenService(installtransaction.ServiceName)
	if e == nil {
		s.Close()
		return errors.New("eGuard NAC service already exists; uninstall first")
	}
	if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return errors.New("eGuard NAC service already exists or cannot be inspected; uninstall first")
	}
	return clearStaleInstall()
}

func clearStaleInstall() error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	entries, _, err := key.GetStringsValue("PendingFileRenameOperations")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	if err == nil {
		filtered := RemovePendingNAC(entries)
		if !reflect.DeepEqual(filtered, entries) {
			if err := key.SetStringsValue("PendingFileRenameOperations", filtered); err != nil {
				return err
			}
		}
	}
	// Only remove our known binary; never delete unrelated files in this directory.
	if err := os.Remove(installtransaction.BinaryPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(filepath.Dir(installtransaction.BinaryPath))
	return nil
}

func (w Windows) Enroll() error {
	b, e := os.ReadFile(w.Bootstrap)
	if e != nil {
		return e
	}
	a, e := os.ReadFile(w.Activation)
	if e != nil {
		return e
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	_, e = admission.Install(provision.Root, b, a, now())
	return e
}

func (w Windows) PlaceBinary() error {
	dir := filepath.Dir(installtransaction.BinaryPath)
	if e := os.MkdirAll(dir, 0755); e != nil { // inherits Program Files ACL: Users read/execute only
		return e
	}
	in, e := os.Open(w.SourceBinary)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(installtransaction.BinaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if e != nil {
		return e
	}
	if _, e = io.Copy(out, in); e != nil {
		out.Close()
		return e
	}
	return out.Close()
}

func (w Windows) RegisterEventLog() error {
	e := eventlog.InstallAsEventCreate(EventSource, eventlog.Error|eventlog.Warning|eventlog.Info)
	if e != nil && !errors.Is(e, windows.ERROR_ALREADY_EXISTS) && !isExists(e) {
		return e
	}
	return nil
}

func isExists(e error) bool { return e != nil && len(e.Error()) > 0 && containsExists(e.Error()) }
func containsExists(s string) bool {
	for i := 0; i+14 <= len(s); i++ {
		if s[i:i+14] == "already exists" {
			return true
		}
	}
	return false
}

func (w Windows) InstallService() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return installtransaction.Run(ctx, installtransaction.NewSCM(), 500*time.Millisecond)
}

func (w Windows) ProtectService() error {
	// Anti-Tamper selection comes only from the verified signed bootstrap.
	c, e := (uninstall.Windows{}).Config()
	if e != nil {
		return e
	}
	if c.AntiTamper == "on" {
		return uninstall.SetServiceDACL(uninstall.ProtectedSDDL)
	}
	return nil
}

func (w Windows) RemoveService() error {
	if e := (uninstall.Windows{}).StopService(); e != nil {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(installtransaction.ServiceName)
	if e != nil {
		return e
	}
	defer s.Close()
	return s.Delete()
}

func (w Windows) RemoveProvisioning() error { return os.RemoveAll(provision.Root) }
func (w Windows) RemoveBinary() error {
	e := os.Remove(installtransaction.BinaryPath)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	_ = os.Remove(filepath.Dir(installtransaction.BinaryPath))
	return nil
}
func (w Windows) RemoveEventLog() error { return eventlog.Remove(EventSource) }
