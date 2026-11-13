package upgrade

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageScripts(t *testing.T) {
	for _, x := range []struct {
		script, arg  string
		enrolled, ok bool
		want         string
	}{
		{"packaging/preremove.sh", "upgrade", true, true, "stop eguard-nac.service"},
		{"packaging/preremove.sh", "1", true, true, "stop eguard-nac.service"},
		{"packaging/preremove.sh", "2", true, true, "stop eguard-nac.service"},
		{"packaging/preremove.sh", "remove", true, false, ""},
		{"packaging/preremove.sh", "purge", true, false, ""},
		{"packaging/preremove.sh", "0", true, false, ""},
		{"packaging/preremove.sh", "remove", false, true, "stop eguard-nac.service\ndisable eguard-nac.service"},
		{"packaging/postinstall.sh", "configure", true, true, "daemon-reload\nenable eguard-nac.service\nstart eguard-nac.service"},
		{"packaging/postinstall.sh", "configure", false, true, "daemon-reload\nenable eguard-nac.service"},
		{"installer/macos/scripts/preinstall", "", true, true, "bootout system/id.eguard.nac"},
		{"installer/macos/scripts/preinstall", "", false, true, ""},
		{"installer/macos/scripts/postinstall", "", true, true, "bootstrap system /Library/LaunchDaemons/id.eguard.nac.plist"},
		{"installer/macos/scripts/postinstall", "", false, true, ""},
	} {
		t.Run(x.script+"/"+x.arg+"/"+map[bool]string{true: "enrolled", false: "fresh"}[x.enrolled], func(t *testing.T) {
			d := t.TempDir()
			log := filepath.Join(d, "calls")
			state := filepath.Join(d, "state.json")
			for _, name := range []string{"systemctl", "launchctl"} {
				if e := os.WriteFile(filepath.Join(d, name), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CALLS\"\n"), 0700); e != nil {
					t.Fatal(e)
				}
			}
			// Fake ownership command: never touch host ownership in sandbox.
			if e := os.WriteFile(filepath.Join(d, "chown"), []byte("#!/bin/sh\nexit 0\n"), 0700); e != nil {
				t.Fatal(e)
			}
			if x.enrolled {
				if e := os.WriteFile(state, []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			plist := filepath.Join(d, "Library/LaunchDaemons")
			os.MkdirAll(plist, 0700)
			os.WriteFile(filepath.Join(plist, "id.eguard.nac.plist"), nil, 0600)
			c := exec.Command("sh", "../"+x.script, x.arg)
			c.Env = append(os.Environ(), "PATH="+d+":"+os.Getenv("PATH"), "CALLS="+log, "EGUARD_NAC_TEST_STATE="+state, "EGUARD_NAC_TEST_ROOT="+d)
			out, e := c.CombinedOutput()
			if (e == nil) != x.ok {
				t.Fatalf("error %v: %s", e, out)
			}
			b, _ := os.ReadFile(log)
			if strings.TrimSpace(string(b)) != x.want {
				t.Fatalf("calls %q want %q", b, x.want)
			}
			if x.script == "installer/macos/scripts/postinstall" {
				target, e := os.Readlink(filepath.Join(d, "usr/local/bin/eguard-nac"))
				if e != nil || target != "/Library/eGuard NAC/eguard-nac-service" {
					t.Fatalf("CLI symlink: %q %v", target, e)
				}
				fi, e := os.Stat(filepath.Join(plist, "id.eguard.nac.plist"))
				if e != nil || fi.Mode().Perm() != 0644 {
					t.Fatal("plist permissions not repaired")
				}
			}
			if x.enrolled {
				b, e := os.ReadFile(state)
				if e != nil || string(b) != "preserve" {
					t.Fatal("state changed")
				}
			}
		})
	}
}
