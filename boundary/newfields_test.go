package boundary

import (
	"eguard-nac-agent/core"
	"testing"
	"time"
)

func TestInventoryUpdatesServicesBounds(t *testing.T) {
	inv := core.Inventory{AgentType: "nac", ObservedAt: time.Now(), UpdatesCollected: true, Updates: []core.UpdateItem{{ID: "KB1"}}}
	if ValidateInventory(inv, false, false) == nil {
		t.Fatal("unrequested updates accepted")
	}
	if ValidateInventory(inv, true, false) != nil {
		t.Fatal("enabled updates rejected")
	}
	inv.Updates = make([]core.UpdateItem, 401)
	if ValidateInventory(inv, true, false) == nil {
		t.Fatal("oversized updates accepted")
	}
}
