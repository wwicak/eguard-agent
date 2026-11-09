package collector

import (
	"eguard-nac-agent/core"
	"testing"
)

func TestRelevantAdapters(t *testing.T) {
	in := []core.Adapter{{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", Addresses: []string{"169.254.1.2/16", "192.168.1.2/24"}, ActiveRoute: true}, {Name: "vEthernet (WSL)", MAC: "aa:bb:cc:dd:ee:01", Addresses: []string{"10.0.0.1/8"}}, {Name: "Wi-Fi", MAC: "", Addresses: []string{"10.0.0.2/8"}}}
	got := RelevantAdapters(in)
	if len(got) != 1 || !got[0].Primary || len(got[0].Addresses) != 1 || got[0].Addresses[0] != "192.168.1.2/24" {
		t.Fatalf("%+v", got)
	}
}
