package upgrade

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPackageVersionPolicy(t *testing.T) {
	for _, x := range []struct {
		old, next     string
		reinstall, ok bool
	}{
		{"1.2.3", "1.3.0", false, true}, {"1.2.3", "1.2.3", false, false}, {"1.2.3", "1.2.3", true, true}, {"2.0.0", "1.0.0", true, false}, {"unknown", "0.1.0", false, true}, {"0.0.0-dev", "0.1.0", false, true}, {"1.0.0-rc.2", "1.0.0-rc.10", false, true}, {"1.0.0", "1.0.0-rc.1", false, false}, {"1.0.0", "01.2.3", false, false}, {"unknown", "invalid", false, false},
	} {
		t.Run(x.old+"-"+x.next, func(t *testing.T) {
			d := t.TempDir()
			binary := filepath.Join(d, "installed")
			os.WriteFile(binary, []byte("#!/bin/sh\necho '"+x.old+"'\n"), 0700)
			c := exec.Command("sh", "../packaging/version-policy.sh")
			reinstall := "0"
			if x.reinstall {
				reinstall = "1"
			}
			c.Env = append(os.Environ(), "NAC_NEW_VERSION="+x.next, "NAC_INSTALLED_BINARY="+binary, "EGUARD_NAC_REINSTALL="+reinstall)
			b, e := c.CombinedOutput()
			if (e == nil) != x.ok {
				t.Fatalf("%v: %s", e, b)
			}
		})
	}
}
