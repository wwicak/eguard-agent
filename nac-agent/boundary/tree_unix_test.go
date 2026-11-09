//go:build !windows

package boundary

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTimeoutKillsChildProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_, err := run(ctx, func() *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		c.Env = append(os.Environ(), "NAC_BOUNDARY_TEST_HELPER=1", "NAC_BOUNDARY_SCENARIO=grandchild", "NAC_TEST_PID_PATH="+pidFile)
		return c
	})
	if err == nil {
		t.Fatal("hung process accepted")
	}
	b, e := os.ReadFile(pidFile)
	if e != nil {
		t.Fatalf("helper did not spawn child: %v", e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil {
		t.Fatal(e)
	}
	// ESRCH or zombie (already dead, awaiting init reaping) are both acceptable.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e = syscall.Kill(pid, 0); e == syscall.ESRCH {
			return
		}
		stat, readErr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if readErr == nil && strings.Contains(string(stat), ") Z ") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("grandchild still running after timeout: pid=%d", pid)
}
