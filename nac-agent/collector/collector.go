// Package collector performs fixed, read-only OS network enumeration. Unavailable signals remain unknown.
package collector

import (
	"eguard-nac-agent/core"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func Classify(name string) string {
	if virtualAdapterName(name) {
		return "virtual"
	}
	// A name alone cannot prove hardware identity.
	return "unknown"
}
func Collect(now time.Time) core.Posture {
	p := collectSnapshot(now)
	p.Adapters = RelevantAdapters(p.Adapters)
	return p
}

func collectSnapshot(now time.Time) core.Posture {
	p := core.Posture{AgentType: "nac", ObservedAt: now, TTL: 5 * time.Minute, OS: runtime.GOOS + "/" + runtime.GOARCH, Domain: core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown}, AV: core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown}, Firewall: map[string]core.Evidence{}}
	for _, profile := range []string{"domain", "private", "public"} {
		p.Firewall[profile] = core.Evidence{Value: core.Unknown, Source: "not-collected", Error: "Windows profile API not integrated"}
	}
	p.Errors = append(p.Errors, "domain and AV provider APIs not integrated; no compliance decision permitted")
	interfaces, err := net.Interfaces()
	var vpnInterfaces []vpnInterface
	if err != nil {
		p.VPN = vpnSnapshot(runtime.GOOS, nil, err, "net.Interfaces")
		p.Errors = append(p.Errors, "interface enumeration failed")
		return p
	}
	for _, iface := range interfaces {
		a := core.Adapter{Name: iface.Name, MAC: iface.HardwareAddr.String(), Kind: Classify(iface.Name), KindSource: "name heuristic; unverified", RouteStatus: core.Unknown}
		if iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			a.Kind = "virtual"
		}
		addresses, e := iface.Addrs()
		vi := vpnInterface{name: iface.Name, up: iface.Flags&net.FlagUp != 0, tunnel: iface.Flags&net.FlagPointToPoint != 0, err: e}
		if e != nil {
			p.Errors = append(p.Errors, "addresses unavailable for "+iface.Name)
		} else {
			for _, addr := range addresses {
				a.Addresses = append(a.Addresses, addr.String())
				vi.addresses = append(vi.addresses, addr.String())
			}
		}
		if runtime.GOOS == "linux" && !linuxPhysicalInterface("/sys/class/net", iface.Name, 0) {
			a.Kind = "virtual"
		}
		p.Adapters = append(p.Adapters, a)
		vpnInterfaces = append(vpnInterfaces, vi)
	}
	p.VPN = vpnSnapshot(runtime.GOOS, vpnInterfaces, nil, "net.Interfaces")
	acquireDefaultRoute(&p)
	return p
}

// Bound recursion and only follow lower links for supported logical interfaces.
func linuxPhysicalInterface(root, name string, depth int) bool {
	if depth > 8 || virtualAdapterName(name) {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, name, "device")); err == nil {
		return true
	}
	logical := false
	if _, err := os.Stat(filepath.Join(root, name, "bonding")); err == nil {
		logical = true
	}
	if b, err := os.ReadFile(filepath.Join(root, name, "uevent")); err == nil && (strings.Contains(string(b), "DEVTYPE=vlan") || strings.Contains(string(b), "DEVTYPE=team")) {
		logical = true
	}
	if !logical {
		return false
	}
	links, _ := filepath.Glob(filepath.Join(root, name, "lower_*"))
	for _, link := range links {
		target, err := filepath.EvalSymlinks(link)
		if err == nil && linuxPhysicalInterface(root, filepath.Base(target), depth+1) {
			return true
		}
	}
	return false
}
