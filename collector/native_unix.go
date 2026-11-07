//go:build linux || darwin

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"eguard-nac-agent/selfenroll"
	"os"
	"time"
)

// CollectNative conservatively reports only directly observed facts. Additional
// platform providers must not turn a missing provider into negative evidence.
func CollectNative(ctx context.Context, expected string) core.Posture {
	p := Collect(time.Now().UTC())
	p.Errors = []string{"Unix security providers not yet integrated; unavailable posture remains Unknown"}
	if h, e := os.Hostname(); e == nil {
		p.Hostname = selfenroll.CleanHostname(h)
	}
	if ctx.Err() != nil {
		p.TTL = 0
	}
	return p
}

func CollectInventory(ctx context.Context, software, user bool) core.Inventory {
	inv := core.Inventory{AgentType: "nac", ObservedAt: time.Now().UTC(), Software: []core.SoftwareItem{}, Errors: []string{}}
	if software {
		inv.Errors = append(inv.Errors, "Unix software inventory provider not yet integrated")
	}
	if user {
		inv.Errors = append(inv.Errors, "Unix signed-in user provider not yet integrated")
	}
	return inv
}
