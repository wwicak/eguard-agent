//go:build windows

package uninstall

import (
	"errors"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"eguard-nac-agent/bootstrap"
	"eguard-nac-agent/cleanup"
	"eguard-nac-agent/installtransaction"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/servicefactory"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Service DACLs (documented SDDL service rights).
//
//	Protected (Anti-Tamper ON): SYSTEM full; Administrators may only query, read,
//	interrogate and start (no stop/pause/config change/delete/WRITE_DAC);
//	Interactive/Service users query+interrogate. A local admin can still take
//	ownership and change this — anti-tamper raises effort, it is not immunity.
//	Default (OFF / during authorized uninstall): Windows default service SDDL.
const (
	ProtectedSDDL = "D:P(A;;CCLCSWRPWPDTLOCRRCSDWDWO;;;SY)(A;;CCLCSWLOCRRCRP;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
	DefaultSDDL   = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
)

// SetServiceDACL applies an SDDL DACL to the NAC service via SetServiceObjectSecurity.
func SetServiceDACL(sddl string) error {
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	h, e := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(installtransaction.ServiceName), windows.WRITE_DAC|windows.READ_CONTROL)
	if e != nil {
		return e
	}
	defer windows.CloseServiceHandle(h)
	r, _, err := procSetServiceObjectSecurity.Call(uintptr(h), uintptr(windows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(sd)))
	if r == 0 {
		return err
	}
	return nil
}

var procSetServiceObjectSecurity = windows.NewLazySystemDLL("advapi32.dll").NewProc("SetServiceObjectSecurity")

type Windows struct{}

func (Windows) Config() (Config, error) {
	in, e := provision.LoadConfig(provision.Root)
	if e != nil {
		return Config{}, e
	}
	v, e := bootstrap.Verify(in.BootstrapBytes, in.BootstrapPin, in.State.Binding, in.State.DurableFloor, in.State.JournalPath)
	if e != nil {
		return Config{}, e
	}
	return Config{AntiTamper: v.AntiTamper(), Keys: v.LifecycleKeys(), Binding: v.Binding(), MachineCert: v.MachineCertSHA256()}, nil
}

func (Windows) StopService() error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(installtransaction.ServiceName)
	if errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if e != nil {
		return e
	}
	defer s.Close()
	st, e := s.Query()
	if e != nil {
		return e
	}
	if st.State != svc.Stopped {
		if _, e = s.Control(svc.Stop); e != nil && !errors.Is(e, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return e
		}
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if st, e = s.Query(); e != nil {
			return e
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("service did not stop")
}

// Handoff writes the request into the protected provisioning root and waits for
// the service verdict (accepted → service performs cleanup; rejected → reason).
func (Windows) Handoff(raw []byte) error {
	res := filepath.Join(provision.Root, servicefactory.ResultFile)
	_ = os.Remove(res)
	tmp := filepath.Join(provision.Root, ".uninstall-request.tmp")
	if e := os.WriteFile(tmp, raw, 0600); e != nil {
		return e
	}
	if e := os.Rename(tmp, filepath.Join(provision.Root, servicefactory.RequestFile)); e != nil {
		_ = os.Remove(tmp)
		return e
	}
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if b, e := os.ReadFile(res); e == nil && len(b) > 0 {
			if string(b) != "accepted" {
				return errors.New("service " + string(b))
			}
			// Wait for the service's own cleanup to remove it.
			for d2 := time.Now().Add(60 * time.Second); time.Now().Before(d2); time.Sleep(250 * time.Millisecond) {
				if _, e := os.Stat(provision.Root); os.IsNotExist(e) {
					return nil
				}
			}
			return errors.New("service accepted uninstall but cleanup did not finish in time")
		}
		if _, e := os.Stat(provision.Root); os.IsNotExist(e) {
			return nil
		}
	}
	_ = os.Remove(filepath.Join(provision.Root, servicefactory.RequestFile))
	return errors.New("service did not respond to uninstall request (is it running?)")
}

func (Windows) Cleanup(fp [32]byte) error {
	return cleanup.Run(cleanup.Windows{ServiceName: installtransaction.ServiceName, ProvisioningRoot: provision.Root, InstallDir: filepath.Dir(installtransaction.BinaryPath)}, fp)
}
