package bootintegration

import (
	"context"
	"eguard-nac-agent/core"
	"encoding/json"
	"testing"
)

func TestVPNWireCompatibility(t *testing.T) {
	p := core.Posture{VPN: &core.VPNEvidence{Connected: core.Yes, Products: []string{"WireGuard"}, Source: "net.Interfaces"}}
	for _, on := range []bool{false, true} {
		sent := false
		send := vpnPostureSender(on, func(_ context.Context, p core.Posture) error {
			sent = true
			b, e := json.Marshal(p)
			if e != nil {
				return e
			}
			var wire map[string]json.RawMessage
			if e = json.Unmarshal(b, &wire); e != nil {
				return e
			}
			if _, has := wire["vpn"]; has != on {
				t.Fatalf("on=%v: %s", on, b)
			}
			return nil
		})
		if e := send(context.Background(), p); e != nil || !sent {
			t.Fatalf("send: %v", e)
		}
	}
	if p.VPN == nil {
		t.Fatal("gate mutated snapshot")
	}
}
