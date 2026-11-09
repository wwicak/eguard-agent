//go:build linux || darwin

package unixagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixedCLIValidation(t *testing.T) {
	for _, args := range [][]string{{"shell"}, {"status", "extra"}, {"enroll", "--server", "bad", "--fingerprint", strings.Repeat("a", 64), "ABCDE23456"}, {"enroll", "--server", "localhost:443", "--fingerprint", "bad", "ABCDE23456"}, {"uninstall", "--token", "x", "--authorization", "y"}} {
		if Main(args) == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
func TestTerminalCleanupTemporaryRootFixedCommands(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nac")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "machine-key.pem"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	var calls []string
	run := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	if e := TerminalCleanup(root, run); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("root remains")
	}
	for _, call := range calls {
		if !strings.Contains(call, "eguard-nac.service") {
			t.Fatalf("unexpected command %s", call)
		}
	}
}
