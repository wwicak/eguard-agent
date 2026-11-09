//go:build !windows

package boundary

import (
	"os/exec"
	"sync"
	"syscall"
)

func prepare(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func attach(cmd *exec.Cmd) (func(), error) {
	var once sync.Once
	return func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		})
	}, nil
}
