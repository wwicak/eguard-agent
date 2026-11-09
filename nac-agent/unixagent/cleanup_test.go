//go:build linux || darwin

package unixagent

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCleanupExactCommandsAndPaths(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			base := t.TempDir()
			p := CleanupPaths{Root: filepath.Join(base, "root"), Plist: filepath.Join(base, "daemon.plist"), CLI: filepath.Join(base, "cli"), InstallDir: filepath.Join(base, "install")}
			for _, path := range []string{p.Root, p.Plist, p.CLI, p.InstallDir} {
				if e := os.WriteFile(path, []byte("fixture"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			var calls []string
			run := func(_ context.Context, n string, a ...string) error {
				calls = append(calls, n+" "+strings.Join(a, " "))
				return nil
			}
			if e := cleanupUnix(platform, p, run); e != nil {
				t.Fatal(e)
			}
			want := []string{"/usr/bin/systemctl disable eguard-nac.service", "/usr/bin/systemctl stop eguard-nac.service"}
			if platform == "darwin" {
				want = []string{"/bin/launchctl bootout system/id.eguard.nac"}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("%v", calls)
			}
			if _, e := os.Stat(p.Root); !os.IsNotExist(e) {
				t.Fatal("root remains")
			}
			if platform == "darwin" {
				for _, path := range []string{p.Plist, p.CLI, p.InstallDir} {
					if _, e := os.Stat(path); !os.IsNotExist(e) {
						t.Fatal(path)
					}
				}
			}
		})
	}
}
