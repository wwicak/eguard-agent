package collector

import (
	"eguard-nac-agent/core"
	"testing"
)

func TestDomainEvidence(t *testing.T) {
	d := normalizeDomain(true, "corp.example", "corp.example")
	if d.Result() != core.Yes {
		t.Fatal(d)
	}
	if normalizeDomain(true, "corp.example", "other.example").Result() != core.No {
		t.Fatal("mismatch")
	}
	if normalizeDomain(true, "", "corp.example").Result() != core.Unknown {
		t.Fatal("missing domain")
	}
}
func TestAVProviderLimits(t *testing.T) {
	a := normalizeAV([]AVProduct{{Name: "Third party", State: 0x1000}}, DefenderStatus{Present: true, AMRunning: false, Realtime: false, SignaturesAge: 2})
	if a.Running != core.Unknown || a.Updated != core.Unknown {
		t.Fatal("opaque vendor state must not assert health", a)
	}
	a = normalizeAV(nil, DefenderStatus{Present: true, AMRunning: true, Realtime: true, SignaturesAge: 1})
	if a.Result() != core.Yes {
		t.Fatal(a)
	}
	a = normalizeAV(nil, DefenderStatus{Present: true, AMRunning: false, Realtime: false, SignaturesAge: 1})
	if a.Running != core.No || a.Updated != core.Unknown {
		t.Fatal("passive Defender")
	}
}
func TestFirewallEvidence(t *testing.T) {
	if normalizeFirewall(nil)["public"].Value != core.Unknown {
		t.Fatal("absent profile is not disabled")
	}
	p := normalizeFirewall(map[string]bool{"public": false})
	if p["public"].Value != core.No || p["domain"].Value != core.Unknown {
		t.Fatal(p)
	}
}
func TestPhysicalProvenance(t *testing.T) {
	if adapterKind("Ethernet", nil) != "unknown" || adapterKind("Ethernet", ptrBool(true)) != "physical" || adapterKind("vEthernet", ptrBool(true)) != "unknown" {
		t.Fatal("conflicting signals")
	}
}
func ptrBool(v bool) *bool { return &v }
