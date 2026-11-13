package collector

import (
	"eguard-nac-agent/core"
	"errors"
	"reflect"
	"testing"
)

func TestVPNSnapshot(t *testing.T) {
	active := func(name string) vpnInterface {
		return vpnInterface{name: name, up: true, addresses: []string{"10.8.0.2/24"}}
	}
	tests := []struct {
		name, os string
		in       []vpnInterface
		err      error
		want     core.Tri
		products []string
	}{
		{"mac VPN", "darwin", []vpnInterface{{name: "utun0", up: true}, {name: "utun1", up: true, addresses: []string{"fe80::1/64"}}, {name: "utun2", up: true}, {name: "utun3", up: true}, active("utun4")}, nil, core.Yes, []string{"macOS VPN (utun)"}},
		{"mac no VPN", "darwin", []vpnInterface{{name: "utun0", up: true, addresses: []string{"fe80::1/64"}}}, nil, core.No, nil},
		{"windows", "windows", []vpnInterface{active("WireGuard Tunnel"), active("TAP-Windows Adapter V9")}, nil, core.Yes, []string{"WireGuard", "OpenVPN"}},
		{"linux", "linux", []vpnInterface{active("wg0"), active("tailscale0")}, nil, core.Yes, []string{"WireGuard", "Tailscale"}},
		{"failed", "linux", nil, errors.New("failed"), core.Unknown, nil},
		{"down", "linux", []vpnInterface{{name: "wg0", addresses: []string{"10.1.1.1"}}}, nil, core.No, nil},
		{"link local", "linux", []vpnInterface{{name: "wg0", up: true, addresses: []string{"169.254.1.1/16", "fe80::1/64"}}}, nil, core.No, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vpnSnapshot(tt.os, tt.in, tt.err, "fixture")
			if got.Connected != tt.want || !reflect.DeepEqual(got.Products, tt.products) {
				t.Fatalf("%+v", got)
			}
			if tt.err != nil && got.Error == "" {
				t.Fatal("missing error")
			}
			var adapters []core.Adapter
			for _, vi := range tt.in {
				adapters = append(adapters, core.Adapter{Name: vi.name, MAC: "02:11:22:33:44:55", Addresses: vi.addresses, Kind: "unknown"})
			}
			if out := relevantAdaptersForOS(tt.os, adapters); len(out) != 0 {
				t.Fatalf("VPN became asset: %+v", out)
			}
		})
	}
}

func TestVPNProductsAndAdapterSeparation(t *testing.T) {
	names := []string{"wg0", "WireGuard Tunnel", "OpenVPN", "tailscale0", "zt123", "Fortinet", "Cisco Secure Client", "PANGP", "Wintun", "ipsec0"}
	var in []vpnInterface
	var adapters []core.Adapter
	for _, n := range names {
		in = append(in, vpnInterface{name: n, up: true, addresses: []string{"2001:db8::1/64"}})
		adapters = append(adapters, core.Adapter{Name: n, MAC: "02:11:22:33:44:55", Addresses: []string{"10.8.0.2/24"}, Kind: Classify(n)})
	}
	got := vpnSnapshot("linux", in, nil, "fixture")
	if got.Connected != core.Yes || len(got.Products) != 8 {
		t.Fatalf("%+v", got)
	}
	for _, p := range got.Products {
		if len(p) > 64 {
			t.Fatal(p)
		}
	}
	if out := RelevantAdapters(adapters); len(out) != 0 {
		t.Fatalf("tunnels retained: %+v", out)
	}
	for name, want := range map[string]string{"tun0": "OpenVPN/TUN", "ppp0": "IPsec/PPP VPN", "GlobalProtect": "GlobalProtect", "Cisco AnyConnect": "Cisco AnyConnect/Secure Client"} {
		if got := vpnProduct("linux", name); got != want {
			t.Fatalf("%s: %s", name, got)
		}
	}
}
