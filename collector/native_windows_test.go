//go:build windows

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Run only on an explicitly authorized Windows VM. t.TempDir is the only output directory.
func TestNativeReadOnlyPosture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := CollectNative(ctx, "")
	if p.AgentType != "nac" || p.Domain.Match != core.Unknown {
		t.Fatalf("invalid NAC identity or unsigned expected domain: %+v", p.Domain)
	}
	if p.ObservedAt.IsZero() || len(p.Firewall) != 3 || p.OS == "unknown" {
		t.Fatal("missing evidence fields")
	}
	for _, a := range p.Adapters {
		if a.Kind == "physical" && a.KindSource == "" {
			t.Fatal("physical adapter without provenance")
		}
		if a.RouteStatus == core.No || (a.ActiveRoute && (a.RouteStatus != core.Yes || a.RouteSource != "GetIpForwardTable2 default IPv4/IPv6 route")) {
			t.Fatal("route absence asserted without evidence")
		}
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(t.TempDir(), "posture-sensitive-VM-only.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("Windows native collection complete: adapters=%d errors=%d; sensitive fixture retained only in temporary test directory", len(p.Adapters), len(p.Errors))
}
