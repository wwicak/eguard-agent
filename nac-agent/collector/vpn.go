package collector

import (
	"eguard-nac-agent/core"
	"net"
	"strings"
)

// vpnInterface is transient acquisition data, never asset inventory or user activity.
type vpnInterface struct {
	name      string
	up        bool
	tunnel    bool
	addresses []string
	err       error
}

func vpnProduct(goos, name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "wireguard"), strings.HasPrefix(n, "wg"):
		return "WireGuard"
	case strings.Contains(n, "tailscale"):
		return "Tailscale"
	case strings.Contains(n, "zerotier"), strings.HasPrefix(n, "zt"):
		return "ZeroTier"
	case strings.Contains(n, "fortinet"), strings.Contains(n, "forticlient"):
		return "FortiClient"
	case strings.Contains(n, "cisco anyconnect"), strings.Contains(n, "cisco secure client"):
		return "Cisco AnyConnect/Secure Client"
	case strings.Contains(n, "pangp"), strings.Contains(n, "globalprotect"):
		return "GlobalProtect"
	case strings.Contains(n, "tap-windows"), strings.Contains(n, "openvpn"):
		return "OpenVPN"
	case strings.Contains(n, "wintun"):
		return "Wintun-based VPN"
	case goos == "darwin" && strings.HasPrefix(n, "utun"):
		return "macOS VPN (utun)"
	case strings.HasPrefix(n, "ipsec"), strings.HasPrefix(n, "ppp"):
		return "IPsec/PPP VPN"
	case strings.HasPrefix(n, "tun"):
		return "OpenVPN/TUN"
	}
	return ""
}

func vpnSnapshot(goos string, in []vpnInterface, enumerationErr error, source string) *core.VPNEvidence {
	v := &core.VPNEvidence{Connected: core.No, Source: source}
	if enumerationErr != nil {
		v.Connected = core.Unknown
		v.Error = "interface enumeration failed"
		return v
	}
	incomplete := false
	seen := map[string]bool{}
	for _, a := range in {
		product := vpnProduct(goos, a.name)
		if (product == "" && !a.tunnel) || !a.up {
			continue
		}
		if a.err != nil {
			incomplete = true
			continue
		}
		active := false
		for _, address := range a.addresses {
			ip, _, err := net.ParseCIDR(address)
			if err != nil {
				ip = net.ParseIP(address)
			}
			// Includes RFC1918/ULA, but excludes link-local, loopback, unspecified and multicast.
			// utun system/Private Relay interfaces cannot be distinguished from a VPN by IP alone.
			if ip != nil && ip.IsGlobalUnicast() {
				active = true
				break
			}
		}
		if !active {
			continue
		}
		v.Connected = core.Yes
		if product != "" && !seen[product] && len(v.Products) < 8 {
			seen[product] = true
			v.Products = append(v.Products, product)
		}
	}
	if incomplete {
		v.Error = "VPN interface addresses unavailable"
		if v.Connected != core.Yes {
			v.Connected = core.Unknown
		}
	}
	return v
}
