package collector

import (
	"eguard-nac-agent/core"
	"strings"
	"testing"
)

func TestBSSBAdapters(t *testing.T) {
	names := []string{"en0", "en7", "en8", "bridge0", "awdl0", "llw0", "anpi0", "ap1", "vmenet0"}
	macs := []string{"14:7d:da:a4:0c:f4", "00:e0:99:00:1e:fd", "ac:de:48:00:11:22", "82:b9:7b:08:64:00", "82:b9:7b:08:64:01", "82:b9:7b:08:64:04", "82:b9:7b:08:64:05", "ba:9f:a7:e7:62:ae", "c2:dd:9a:ca:c8:3d"}
	var in []core.Adapter
	for i, name := range names {
		in = append(in, core.Adapter{Name: name, MAC: macs[i], Addresses: []string{"192.0.2.2/24"}})
	}
	if got := relevantAdaptersForOS("darwin", in); len(got) != 2 {
		t.Fatalf("want Wi-Fi + USB LAN, got %+v", got)
	}
}

func TestAdapterValidationAndRouteDedup(t *testing.T) {
	in := []core.Adapter{
		{Name: "eth0", MAC: "14:7d:da:a4:0c:f4", Addresses: []string{"192.0.2.1/24"}},
		{Name: "bond0", MAC: "14:7d:da:a4:0c:f4", ActiveRoute: true},
		{Name: "en0", MAC: "01:00:5e:00:00:01", ActiveRoute: true},
		{Name: "en1", MAC: "00:00:00:00:00:00", ActiveRoute: true},
		{Name: "en2", MAC: "00:e0:99:00:1e:fd", Addresses: []string{"fe80::1/64", "169.254.1.1/16"}},
	}
	got := RelevantAdapters(in)
	if len(got) != 1 || got[0].Name != "bond0" || !got[0].Primary {
		t.Fatalf("%+v", got)
	}
}

func TestVirtualAdapterNames(t *testing.T) {
	for _, name := range []string{"veth123", "docker0", "tailscale0", "wg0", "br-abc", "VMware Ethernet", "vEthernet (WSL)", "Tailscale", "Microsoft Wi-Fi Direct Virtual Adapter", "Bluetooth Device (Personal Area Network)", "iBridge"} {
		osName := "windows"
		if strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "br-") {
			osName = "linux"
		}
		if got := relevantAdaptersForOS(osName, []core.Adapter{{Name: name, MAC: "00:e0:99:00:1e:fd", ActiveRoute: true, Addresses: []string{"192.0.2.1/24"}}}); len(got) != 0 {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestMacVirtualPrefixes(t *testing.T) {
	for _, name := range []string{"AP1", "feth0", "vmenet0"} {
		if !virtualAdapterNameForOS("darwin", name) {
			t.Fatal(name)
		}
	}
}
