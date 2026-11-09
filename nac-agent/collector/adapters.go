package collector

import (
	"eguard-nac-agent/core"
	"net"
	"strings"
)

// RelevantAdapters is a pure projection of the read-only interface snapshot.
func RelevantAdapters(in []core.Adapter) []core.Adapter {
	var out []core.Adapter
	primary := false
	for _, a := range in {
		name := strings.ToLower(a.Name)
		skip := a.MAC == "" || a.Kind == "virtual"
		for _, term := range []string{"loopback", "vmware", "virtualbox", "vethernet", "hyper-v", "wsl", "docker", "tailscale", "wireguard", "tap", "tunnel"} {
			if strings.Contains(name, term) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		a.Addresses = nil
		for _, addr := range inAddresses(in, a.Name, a.MAC) {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			a.Addresses = append(a.Addresses, addr)
		}
		if len(a.Addresses) == 0 {
			continue
		}
		a.Primary = a.ActiveRoute && !primary
		if a.Primary {
			primary = true
		}
		out = append(out, a)
	}
	return out
}
func inAddresses(in []core.Adapter, name, mac string) []string {
	for _, a := range in {
		if a.Name == name && a.MAC == mac {
			return a.Addresses
		}
	}
	return nil
}
