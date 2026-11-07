//go:build linux || darwin

package unixagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"eguard-nac-agent/servicefactory"
)

// Under systemd ProtectSystem=strict the service may write inside its state
// directory but not unlink the directory itself. Official cleanup must still
// remove every credential and state file (Temporary expiry included).
func TestLinuxCleanupEmptiesRootWhenParentNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "eguard-nac")
	if e := os.MkdirAll(filepath.Join(root, "sub"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"machine-key.pem", "journal.db", "state.json", "sub/x"} {
		if e := os.WriteFile(filepath.Join(root, n), []byte("x"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Chmod(parent, 0500); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(parent, 0700)
	run := func(context.Context, string, ...string) error { return nil }
	if e := cleanupUnix("linux", CleanupPaths{Root: root}, run); e != nil {
		t.Fatal(e)
	}
	left, _ := os.ReadDir(root)
	if len(left) != 0 {
		t.Fatalf("state left behind: %v", left)
	}
}

// The CLI must treat "accepted" as in progress, and finish (removing the empty
// state directory it is allowed to remove) once the service has cleaned up.
func TestHandoffWaitsForAcceptedCleanup(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "eguard-nac")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(filepath.Join(root, "state.json"), []byte("{}"), 0600)
	go func() {
		for {
			if _, e := os.Stat(filepath.Join(root, servicefactory.RequestFile)); e == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		_ = os.WriteFile(filepath.Join(root, servicefactory.ResultFile), []byte("accepted"), 0600)
		time.Sleep(300 * time.Millisecond)
		entries, _ := os.ReadDir(root)
		for _, x := range entries {
			_ = os.RemoveAll(filepath.Join(root, x.Name()))
		}
	}()
	if e := (removal{root: root}).Handoff([]byte("{}")); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(root); !os.IsNotExist(e) {
		t.Fatal("empty state directory not removed")
	}
}

func TestHandoffReportsRejection(t *testing.T) {
	root := filepath.Join(t.TempDir(), "eguard-nac")
	_ = os.Mkdir(root, 0700)
	go func() {
		for {
			if _, e := os.Stat(filepath.Join(root, servicefactory.RequestFile)); e == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		_ = os.WriteFile(filepath.Join(root, servicefactory.ResultFile), []byte("rejected: replay"), 0600)
	}()
	if e := (removal{root: root}).Handoff([]byte("{}")); e == nil {
		t.Fatal("rejection not reported")
	}
}
