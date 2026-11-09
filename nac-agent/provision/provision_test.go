package provision

import (
	"eguard-nac-agent/lifecycle"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sample() State {
	return State{Version: 1, Binding: lifecycle.Binding{Issuer: "issuer", DeviceID: "device", TenantID: "tenant", SiteID: "site", EnrollmentID: "enroll"}, DurableFloor: 2, JournalPath: JournalPath}
}
func TestStrictState(t *testing.T) {
	s := sample()
	raw, err := encodeState(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{`{"version":1,"version":1}`, string(raw) + ` {}`, strings.Replace(string(raw), `"version":1`, `"version":1,"extra":2`, 1), strings.Replace(string(raw), `"DeviceID":"device"`, `"DeviceID":"device","DeviceID":"evil"`, 1), strings.Replace(string(raw), `"durable_floor":2`, `"durable_floor":0`, 1)} {
		if _, e := decodeState([]byte(v)); e == nil {
			t.Errorf("accepted %s", v)
		}
	}
	if _, e := decodeState(raw); e != nil {
		t.Fatal(e)
	}
}
func TestFloorAndBinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		// t.TempDir is owned by the test user, not SYSTEM/Administrators; the
		// Windows ACL policy rightly rejects it. Windows coverage: TestWindowsACLIntegration.
		t.Skip("portable semantics test; Windows path covered by ACL integration test")
	}
	BootstrapPinHex = strings.Repeat("01", 32)
	defer func() { BootstrapPinHex = "" }()
	root := t.TempDir()
	s := sample()
	if e := Write(root, s, []byte("signed")); e != nil {
		t.Fatal(e)
	}
	if e := Write(root, s, []byte("signed")); e == nil {
		t.Fatal("overwrite without Replace")
	}
	if e := RaiseFloor(root, 3); e != nil {
		t.Fatal(e)
	}
	if e := RaiseFloor(root, 2); e == nil {
		t.Fatal("floor lowered")
	}
	got, e := Load(root)
	if e != nil || got.State.DurableFloor != 3 {
		t.Fatalf("%+v %v", got, e)
	}
	s.DurableFloor = 2
	if e = Write(root, s, []byte("signed")); e == nil {
		t.Fatal("downgrade")
	}
	s.Binding.DeviceID = "different"
	s.DurableFloor = 4
	if e = Write(root, s, []byte("signed")); e == nil {
		t.Fatal("binding change")
	}
	if _, e = os.Stat(filepath.Join(root, "journal.db")); e != nil {
		t.Fatal(e)
	}
}
