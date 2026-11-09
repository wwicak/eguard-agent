package avvendor

import (
	"strings"
	"testing"
)

func TestRegistryDefenderAndIsolation(t *testing.T) {
	d, ok := Lookup("microsoft-defender")
	if !ok || d.DisplayName != "Microsoft Defender Antivirus" || d.ExampleHours != 72 || d.Query == "" || d.ParseDate == nil || d.TemplateID != "av-signatures-stale" {
		t.Fatalf("defender descriptor: %+v %v", d, ok)
	}
	d.ID = "mutated"
	if got, _ := Lookup("microsoft-defender"); got.ID != "microsoft-defender" {
		t.Fatal("registry mutable")
	}
	if _, ok := Lookup("not-a-reviewed-vendor"); ok {
		t.Fatal("unsupported vendor registered")
	}
	// Production registry may grow only by reviewed vendors. Every entry must
	// be complete; adding a vendor means adding it here deliberately.
	reviewed := map[string]bool{"microsoft-defender": true, "crowdstrike": true, "symantec": true, "mcafee-trellix": true,
		// R2: third-party candidate locations, approved by Boss without lab verification.
		"malwarebytes": true, "fortinet": true, "trendmicro": true, "eset": true, "avast": true, "avg": true, "fsecure": true, "gdata": true, "panda": true, "vipre": true,
		// R3: cloud/ML/EOL products, approved by Boss.
		"carbonblack": true, "forefront": true, "webroot": true, "cylance": true, "rising": true, "mse": true, "caetrust": true, "activevirusshield": true,
		// Leftover R1-R3, approved by Boss.
		"sophos": true, "avira": true, "hauri": true, "k7": true, "estsoft": true, "escan": true, "360safe": true, "ivanti-landesk": true,
		"ntw": true, "bitdefender": true, "kaspersky": true, "clamav": true, "comodo": true, "ahnlab": true, "paloalto": true}
	for _, got := range All() {
		if got.ID != "microsoft-defender" && got.ID != "crowdstrike" && got.ID != "symantec" && got.ID != "mcafee-trellix" && !strings.HasSuffix(got.DisplayName, "(unverified)") {
			t.Fatalf("R2 vendor must be labelled unverified: %+v", got)
		}
		if !reviewed[got.ID] || got.Collect == nil || got.TemplateID == "" || (!got.StatusOnly && got.ExampleHours <= 0) || got.DisplayName == "" {
			t.Fatalf("unreviewed or incomplete vendor descriptor: %+v", got)
		}
	}
}
