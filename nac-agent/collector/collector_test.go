package collector

import (
	"eguard-nac-agent/core"
	"testing"
	"time"
)

func TestUnknownEvidenceNeverClaimed(t *testing.T) {
	p := Collect(time.Now())
	if p.Domain.Result() != core.Unknown || p.AV.Result() != core.Unknown {
		t.Fatal("unverified evidence asserted")
	}
	for _, v := range p.Firewall {
		if v.Value != core.Unknown {
			t.Fatal("unverified firewall asserted")
		}
	}
}
func TestAdapterClassification(t *testing.T) {
	if Classify("vEthernet (Default Switch)") != "virtual" || Classify("Ethernet") != "unknown" {
		t.Fatal("classification fabricated physical adapter")
	}
}
