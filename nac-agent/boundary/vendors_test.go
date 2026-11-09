package boundary

import (
	"eguard-nac-agent/core"
	"testing"
	"time"
)

func TestValidateVendors(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	d := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	ok := []core.AVVendorEvidence{{ID: "kaspersky", Active: "enabled", SignatureLastUpdated: &d}, {ID: "eset", Active: "absent"}, {ID: "microsoft-defender", Active: "unknown", SignatureLastUpdated: &d}}
	if err := ValidateVendors(ok, now); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]core.AVVendorEvidence{
		"unknown id":    {{ID: "not-a-vendor", Active: "enabled"}},
		"dup":           {{ID: "eset", Active: "enabled"}, {ID: "eset", Active: "disabled"}},
		"bad state":     {{ID: "eset", Active: "running"}},
		"future date":   {{ID: "eset", Active: "enabled", SignatureLastUpdated: &future}},
		"absent w date": {{ID: "eset", Active: "absent", SignatureLastUpdated: &d}},
	} {
		if ValidateVendors(bad, now) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
