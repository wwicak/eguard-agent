//go:build windows

package provision

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsACLIntegration(t *testing.T) {
	if os.Getenv("EGUARD_NAC_PROVISION_ITEST") != "1" {
		t.Skip("opt-in administrator Windows test")
	}
	BootstrapPinHex = strings.Repeat("01", 32)
	defer func() { BootstrapPinHex = "" }()
	// Never create or touch the production Root here: a test-created Root would
	// inherit ProgramData's user-writable ACL and later block (fail-closed) a real
	// install. Use a sibling temp name and let Write/prepareRoot create it with the
	// protected DACL, which is exactly the installer path under test.
	probe, e := os.MkdirTemp(filepath.Dir(Root), "eGuard NAC ITEST-")
	if e != nil {
		t.Fatal(e)
	}
	root := probe
	if e = os.Remove(probe); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	if e = Write(root, sample(), []byte("signed envelope")); e != nil {
		t.Fatal(e)
	}
	if e = checkPath(root); e != nil {
		t.Fatalf("Write-created root not accepted: %v", e)
	}
	// Same semantics as the portable TestFloorAndBinding, on a real protected root.
	s := sample()
	if e = Write(root, s, []byte("signed envelope")); e == nil {
		t.Fatal("overwrite without Replace")
	}
	if e = RaiseFloor(root, 3); e != nil {
		t.Fatal(e)
	}
	if e = RaiseFloor(root, 2); e == nil {
		t.Fatal("floor lowered")
	}
	s.DurableFloor, s.Replace = 3, true
	s.Binding.DeviceID = "different"
	if e = Write(root, s, []byte("signed envelope")); e == nil {
		t.Fatal("binding change accepted")
	}
	for _, f := range []string{StateFile, BootstrapFile, "journal.db"} {
		if e = checkPath(filepath.Join(root, f)); e != nil {
			t.Fatalf("%s not protected: %v", f, e)
		}
	}
	if _, e = Load(root); e != nil {
		t.Fatal(e)
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GW;;;WD)")
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, StateFile)
	if e = windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(root); e == nil {
		t.Fatal("Everyone write accepted")
	}
	// A root pre-created with ProgramData's inherited ACL (Users may create/write)
	// must be refused by both Load and Write rather than adopted.
	weak, e := os.MkdirTemp(filepath.Dir(Root), "eGuard NAC ITEST-weak-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(weak)
	if e = checkPath(weak); e == nil {
		t.Fatal("inherited ProgramData ACL accepted as provisioning root")
	}
	if e = Write(weak, sample(), []byte("signed envelope")); e == nil {
		t.Fatal("Write adopted a pre-existing weak root")
	}
}
