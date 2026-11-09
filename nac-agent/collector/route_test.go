package collector

import (
	"eguard-nac-agent/core"
	"testing"
)

func TestIPv6DefaultRouteAndUnknown(t *testing.T) {
	cases := []struct {
		prefix string
		index  uint32
		want   core.Tri
	}{{"::/0", 7, core.Yes}, {"2001:db8::/32", 7, core.Unknown}, {"::/0", 0, core.Unknown}}
	for _, c := range cases {
		if got := routeEvidence(7, nil, []routeRecord{{Index: c.index, Prefix: c.prefix}}, true); got != c.want {
			t.Fatalf("%+v => %s", c, got)
		}
	}
	if routeEvidence(7, nil, nil, false) != core.Unknown {
		t.Fatal("failed provider asserted no route")
	}
	if routeEvidence(7, nil, nil, true) != core.Unknown {
		t.Fatal("absence cannot assert no route")
	}
}
func TestOSVersionUnknown(t *testing.T) {
	if osBuild(0, 0, 0) != "unknown" || osBuild(10, 0, 22631) != "windows-10.0.22631" {
		t.Fatal("invented OS version")
	}
}
func TestPhysicalRequiresPnP(t *testing.T) {
	if adapterKind("Ethernet", nil) == "physical" {
		t.Fatal("name is not PnP evidence")
	}
}
