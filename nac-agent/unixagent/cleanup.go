//go:build linux || darwin

package unixagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// CleanupPaths are fixed NAC resources in production, injectable temporary paths
// in tests. Linux binaries remain package-owned: remove the package after cleanup.
type CleanupPaths struct{ Root, Plist, InstallDir, CLI string }

func productionCleanupPaths(root string) CleanupPaths {
	p := CleanupPaths{Root: root}
	if runtime.GOOS == "darwin" {
		p.Plist = "/Library/LaunchDaemons/id.eguard.nac.plist"
		p.InstallDir = "/Library/eGuard NAC"
		p.CLI = "/usr/local/bin/eguard-nac"
	}
	return p
}
func cleanupUnix(platform string, p CleanupPaths, run Runner) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if platform == "linux" {
		// Do not stop ourselves before removing state. The verified service has already
		// closed transport, journal and credential before terminal cleanup is called.
		if e := run(ctx, "/usr/bin/systemctl", "disable", "eguard-nac.service"); e != nil {
			return e
		}
		// systemd ProtectSystem=strict lets the service write inside its state
		// directory but not unlink the directory itself. Remove every entry
		// (credential, journal, provisioning); an empty, root-only directory is
		// not enrollment. The CLI or package removal deletes the empty directory.
		if e := emptyDir(p.Root); e != nil {
			return e
		}
		if e := os.Remove(p.Root); e != nil && !os.IsNotExist(e) && !os.IsPermission(e) && !errors.Is(e, syscall.EROFS) {
			return e
		}
		return run(ctx, "/usr/bin/systemctl", "stop", "eguard-nac.service")
	}
	if platform != "darwin" {
		return errors.New("unsupported cleanup platform")
	}
	// Remove KeepAlive registration from disk before bootout (which can terminate
	// the caller). launchd cannot restart a removed executable after reboot.
	for _, path := range []string{p.Plist, p.Root, p.CLI, p.InstallDir} {
		if path != "" {
			if e := os.RemoveAll(path); e != nil {
				return e
			}
		}
	}
	return run(ctx, "/bin/launchctl", "bootout", "system/id.eguard.nac")
}

func emptyDir(dir string) error {
	i, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !i.IsDir() {
		return os.Remove(dir)
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, x := range entries {
		if e := os.RemoveAll(filepath.Join(dir, x.Name())); e != nil {
			return e
		}
	}
	return nil
}
