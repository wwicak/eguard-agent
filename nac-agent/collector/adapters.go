package collector

import (
	"eguard-nac-agent/core"
	"net"
	"runtime"
	"strings"
)

func virtualAdapterName(name string) bool { return virtualAdapterNameForOS(runtime.GOOS, name) }

func virtualAdapterNameForOS(osName, name string) bool {
	n := strings.ToLower(name)
	if vpnProduct(osName, name) != "" {
		return true
	}
	var prefixes []string
	switch osName {
	case "darwin":
		prefixes = []string{"lo", "awdl", "llw", "utun", "bridge", "p2p", "anpi", "ap", "stf", "gif", "vmenet", "feth", "ipsec", "ppp"}
	case "linux":
		prefixes = []string{"lo", "veth", "docker", "br-", "virbr", "vnet", "tun", "tap", "tailscale", "wg", "zt", "flannel", "cni", "cali", "kube", "vxlan", "genev", "dummy", "ifb", "sit", "ip6tnl", "gre"}
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	for _, term := range []string{"ibridge", "hyper-v", "vethernet", "vmware", "virtualbox", "vbox", "wsl", "tailscale", "wireguard", "tap-", "tap-windows", "wintun", "openvpn", "npcap loopback", "bluetooth pan", "personal area network", "microsoft wi-fi direct virtual", "kernel debug", "wan miniport", "teredo", "isatap", "loopback", "tunnel"} {
		if strings.Contains(n, term) {
			return true
		}
	}
	return false
}

// RelevantAdapters projects a snapshot after route/physical evidence is acquired.
// Locally administered unicast MACs are valid; random-bit heuristics are unsafe.
func RelevantAdapters(in []core.Adapter) []core.Adapter {
	return relevantAdaptersForOS(runtime.GOOS, in)
}

func relevantAdaptersForOS(osName string, in []core.Adapter) []core.Adapter {
	var out []core.Adapter
	seen := map[string]int{}
	for _, a := range in {
		mac, err := net.ParseMAC(a.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" || mac.String() == "ac:de:48:00:11:22" || a.Kind == "virtual" || virtualAdapterNameForOS(osName, a.Name) {
			continue
		}
		addresses := a.Addresses
		a.Addresses = nil
		for _, addr := range addresses {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				ip = net.ParseIP(addr)
			}
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			a.Addresses = append(a.Addresses, addr)
		}
		if len(a.Addresses) == 0 && !a.ActiveRoute {
			continue
		}
		key := mac.String()
		if i, ok := seen[key]; ok {
			if a.ActiveRoute && !out[i].ActiveRoute {
				out[i] = a
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, a)
	}
	primary := false
	for i := range out {
		out[i].Primary = out[i].ActiveRoute && !primary
		primary = primary || out[i].Primary
	}
	return out
}
