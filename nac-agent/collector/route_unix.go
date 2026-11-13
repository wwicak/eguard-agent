//go:build linux || darwin

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func acquireDefaultRoute(p *core.Posture) {
	if runtime.GOOS == "linux" {
		b, _ := os.ReadFile("/proc/net/route")
		applyRoute(p, parseLinuxRoute(string(b)), "/proc/net/route")
		b, _ = os.ReadFile("/proc/net/ipv6_route")
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" {
				flags, err := strconv.ParseUint(f[8], 16, 32)
				if err == nil && flags&1 != 0 && flags&0x200 == 0 {
					applyRoute(p, f[9], "/proc/net/ipv6_route")
				}
			}
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if b, err := runUnix(ctx, "/sbin/route", "-n", "get", "default"); err == nil {
			applyRoute(p, parseMacRoute(string(b)), "route default")
		}
	}
}
