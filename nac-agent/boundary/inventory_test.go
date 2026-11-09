package boundary

import (
	"eguard-nac-agent/core"
	"testing"
	"time"
)

func TestValidateInventory(t *testing.T) {
	ok := core.Inventory{AgentType: "nac", ObservedAt: time.Now(), SoftwareCollected: true, Software: []core.SoftwareItem{{Name: "Zoom", Version: "6"}}}
	if err := ValidateInventory(ok, true, false); err != nil {
		t.Fatal(err)
	}
	if ValidateInventory(ok, false, false) == nil {
		t.Fatal("software not enabled must be refused")
	}
	u := core.Inventory{AgentType: "nac", ObservedAt: time.Now(), User: "CORP\\budi"}
	if ValidateInventory(u, false, true) == nil {
		t.Fatal("user without user_collected must be refused")
	}
	u.UserCollected = true
	if ValidateInventory(u, false, true) != nil || ValidateInventory(u, true, false) == nil {
		t.Fatal("user flag")
	}
	bad := ok
	bad.Software = []core.SoftwareItem{{Name: ""}}
	if ValidateInventory(bad, true, false) == nil {
		t.Fatal("unnamed software accepted")
	}
}
