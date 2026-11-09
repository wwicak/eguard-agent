package collector

import (
	"context"
	"eguard-nac-agent/core"
)

func CollectNative(ctx context.Context, expected string) core.Posture {
	return nativeProvider().MacPosture(ctx, expected)
}
func CollectInventory(ctx context.Context, software, user bool) core.Inventory {
	return nativeProvider().MacInventory(ctx, software, user)
}
