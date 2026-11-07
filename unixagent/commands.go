//go:build linux || darwin

package unixagent

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"time"
)

type Runner func(context.Context, string, ...string) error

// RunFixed is private to the adapter; callers cannot supply command paths via CLI.
func runCommand(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}
func serviceCommand(run Runner, verb string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if runtime.GOOS == "linux" {
		switch verb {
		case "start":
			if e := run(ctx, "/usr/bin/systemctl", "enable", "eguard-nac.service"); e != nil {
				return e
			}
			return run(ctx, "/usr/bin/systemctl", "start", "eguard-nac.service")
		case "stop":
			return run(ctx, "/usr/bin/systemctl", "stop", "eguard-nac.service")
		case "disable":
			return run(ctx, "/usr/bin/systemctl", "disable", "eguard-nac.service")
		}
	} else {
		switch verb {
		case "start":
			return run(ctx, "/bin/launchctl", "bootstrap", "system", "/Library/LaunchDaemons/id.eguard.nac.plist")
		case "stop":
			return run(ctx, "/bin/launchctl", "bootout", "system/id.eguard.nac")
		case "disable":
			return nil
		}
	}
	return errors.New("unsupported service operation")
}
