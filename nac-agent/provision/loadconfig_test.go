package provision

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"eguard-nac-agent/journal"
)

// LoadConfig must work while the running service holds journal.db exclusively
// (bbolt file lock) — Load cannot — and must still reject missing/invalid state.
func TestLoadConfigWhileJournalLocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable semantics; Windows ACL covered by integration test")
	}
	BootstrapPinHex = strings.Repeat("01", 32)
	defer func() { BootstrapPinHex = "" }()
	root := t.TempDir()
	s := sample()
	if e := Write(root, s, []byte("signed")); e != nil {
		t.Fatal(e)
	}
	held, e := journal.Open(filepath.Join(root, "journal.db"), journalBinding(s.Binding))
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	if _, e := Load(root); e == nil {
		t.Fatal("Load succeeded with journal locked; test premise invalid")
	}
	got, e := LoadConfig(root)
	if e != nil || got.State.Binding != s.Binding || string(got.BootstrapBytes) != "signed" {
		t.Fatalf("%+v %v", got, e)
	}
	if e := os.Remove(filepath.Join(root, StateFile)); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadConfig(root); e == nil {
		t.Fatal("missing state accepted")
	}
	BootstrapPinHex = ""
	if _, e := LoadConfig(root); e == nil {
		t.Fatal("missing pin accepted")
	}
}
