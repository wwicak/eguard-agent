package bootintegration

import (
	"context"
	"eguard-nac-agent/core"
)

// Gate at the last send boundary so every runtime/retry path remains compatible
// with strict legacy servers. Only verified signed config can enable the field.
func vpnPostureSender(enabled bool, send func(context.Context, core.Posture) error) func(context.Context, core.Posture) error {
	return func(ctx context.Context, p core.Posture) error {
		if !enabled {
			p.VPN = nil
		}
		return send(ctx, p)
	}
}
