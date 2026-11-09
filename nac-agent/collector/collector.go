// Package collector performs fixed, read-only OS network enumeration. Unavailable signals remain unknown.
package collector

import (
	"eguard-nac-agent/core"
	"net"
	"runtime"
	"strings"
	"time"
)

func Classify(name string) string {
	n := strings.ToLower(name)
	for _, marker := range []string{"hyper-v", "vmware", "virtualbox", "vbox", "vethernet", "loopback", "tunnel", "wsl", "docker", "tap", "wireguard", "tailscale"} {
		if strings.Contains(n, marker) {
			return "virtual"
		}
	}
	// A name alone cannot prove hardware identity.
	return "unknown"
}
func Collect(now time.Time) core.Posture {
	p := core.Posture{AgentType: "nac", ObservedAt: now, TTL: 5 * time.Minute, OS: runtime.GOOS + "/" + runtime.GOARCH, Domain: core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown}, AV: core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown}, Firewall: map[string]core.Evidence{}}
	for _, profile := range []string{"domain", "private", "public"} {
		p.Firewall[profile] = core.Evidence{Value: core.Unknown, Source: "not-collected", Error: "Windows profile API not integrated"}
	}
	p.Errors = append(p.Errors, "domain and AV provider APIs not integrated; no compliance decision permitted")
	interfaces, err := net.Interfaces()
	if err != nil {
		p.Errors = append(p.Errors, "interface enumeration failed")
		return p
	}
	for _, iface := range interfaces {
		a := core.Adapter{Name: iface.Name, MAC: iface.HardwareAddr.String(), Kind: Classify(iface.Name), KindSource: "name heuristic; unverified", RouteStatus: core.Unknown}
		addresses, e := iface.Addrs()
		if e != nil {
			p.Errors = append(p.Errors, "addresses unavailable for "+iface.Name)
		} else {
			for _, addr := range addresses {
				a.Addresses = append(a.Addresses, addr.String())
			}
		}
		p.Adapters = append(p.Adapters, a)
	}
	return p
}
