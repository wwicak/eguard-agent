package collector

import (
	"testing"

	"eguard-nac-agent/avvendor"
)

func TestPrioritizeVendorsPutsSecurityCenterProductsFirst(t *testing.T) {
	all := avvendor.All()
	got := prioritizeVendors(all, []string{"Windows Defender", "CrowdStrike Falcon Sensor"})
	if len(got) != len(all) {
		t.Fatalf("lost vendors: %d vs %d", len(got), len(all))
	}
	ids := map[string]int{}
	for i, d := range got {
		ids[d.ID] = i
	}
	if ids["crowdstrike"] > 1 || ids["microsoft-defender"] > 1 {
		t.Fatalf("installed vendors not first: crowdstrike=%d defender=%d", ids["crowdstrike"], ids["microsoft-defender"])
	}
	// No products: original order.
	same := prioritizeVendors(all, nil)
	for i := range all {
		if same[i].ID != all[i].ID {
			t.Fatalf("order changed without products at %d", i)
		}
	}
}
