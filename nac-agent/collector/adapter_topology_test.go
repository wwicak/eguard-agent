package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxPhysicalTopology(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"eth0/device", "wlan0/device", "docker0", "veth123/device", "tailscale0", "bond0/bonding", "eth0.10", "mystery"} {
		if err := os.MkdirAll(filepath.Join(root, n), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "eth0.10/uevent"), []byte("DEVTYPE=vlan\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"bond0", "eth0.10", "mystery"} {
		if err := os.Symlink(filepath.Join(root, "eth0"), filepath.Join(root, n, "lower_eth0")); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"eth0", "wlan0", "bond0", "eth0.10"} {
		if !linuxPhysicalInterface(root, n, 0) {
			t.Errorf("rejected %s", n)
		}
	}
	for _, n := range []string{"docker0", "veth123", "tailscale0", "mystery"} {
		if linuxPhysicalInterface(root, n, 0) {
			t.Errorf("accepted %s", n)
		}
	}
}

func TestOSSpecificNames(t *testing.T) {
	if virtualAdapterNameForOS("windows", "Apple USB Ethernet Adapter") {
		t.Fatal("Apple hardware mistaken for ap* macOS interface")
	}
	if virtualAdapterNameForOS("linux", "ap1") {
		t.Fatal("Linux AP is not macOS ap*")
	}
}
