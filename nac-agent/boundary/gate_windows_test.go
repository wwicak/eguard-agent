//go:build windows

package boundary

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// Executed on an approved Windows VM only: exercises the real Start→Job
// assignment path via run, and an ungated helper via os/exec.
func TestWindowsUngatedHelperExits(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "NAC_BOUNDARY_TEST_HELPER=1", "NAC_BOUNDARY_SCENARIO=hang")
	cmd.Stdin = nil // os.DevNull: no release byte
	cmd.WaitDelay = time.Second
	start := time.Now()
	err := cmd.Run()
	if err == nil || time.Since(start) > GateTimeout+3*time.Second {
		t.Fatalf("ungated child did not fail promptly: %v", err)
	}
}
