//go:build linux || darwin

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"os"
	"path/filepath"
	"time"
)

func (u UnixProvider) MacPosture(ctx context.Context, expected string) core.Posture {
	p := Collect(u.Now())
	p.Errors = nil
	p.Firewall = map[string]core.Evidence{"host": ev(core.Unknown, "socketfilterfw"), "gatekeeper": ev(core.Unknown, "spctl")}
	if b, e := u.command(ctx, "/usr/bin/sw_vers"); e == nil {
		if s := parseSWVers(string(b)); s != "" {
			p.OS = s
		}
	}
	if b, e := u.command(ctx, "/usr/sbin/scutil", "--get", "ComputerName"); e == nil {
		p.Hostname = cleanText(string(b))
	}
	if b, e := u.command(ctx, "/sbin/route", "-n", "get", "default"); e == nil {
		applyRoute(&p, parseMacRoute(string(b)), "route default")
	}
	d := ""
	if b, e := u.command(ctx, "/usr/sbin/dsconfigad", "-show"); e == nil {
		d = parseMacDomain(string(b))
	}
	applyDomain(&p, d, expected, "dsconfigad")
	p.Device = &core.DeviceEvidence{SecureBoot: ev(core.Unknown, "not collected"), BitlockerOS: ev(core.Unknown, "FileVault"), PendingReboot: ev(core.Unknown, "not collected")}
	for _, c := range []struct {
		kind, name string
		args       []string
	}{{"firewall", "/usr/libexec/ApplicationFirewall/socketfilterfw", []string{"--getglobalstate"}}, {"filevault", "/usr/bin/fdesetup", []string{"status"}}, {"gatekeeper", "/usr/sbin/spctl", []string{"--status"}}} {
		if b, e := u.command(ctx, c.name, c.args...); e == nil {
			v := parseMacState(c.kind, string(b))
			switch c.kind {
			case "firewall":
				p.Firewall["host"] = ev(v, "socketfilterfw")
			case "filevault":
				p.Device.BitlockerOS = ev(v, "FileVault")
			case "gatekeeper":
				p.Firewall["gatekeeper"] = ev(v, "spctl (not network firewall)")
			}
		}
	}
	xp := "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
	if m := parseXMLPlist(u.read(xp)); m["CFBundleShortVersionString"] != "" {
		updated := core.Unknown
		if i, e := os.Stat(u.path(xp)); e == nil {
			updated = signatureFresh(i.ModTime(), u.Now(), 30*24*time.Hour)
		}
		addAV(&p, "XProtect "+m["CFBundleShortVersionString"], core.Unknown, updated)
	}
	for _, v := range []struct{ name, path string }{{"CrowdStrike", "/Applications/Falcon.app"}, {"SentinelOne", "/Applications/SentinelOne/SentinelOne.app"}, {"Sophos", "/Applications/Sophos/Sophos Endpoint.app"}, {"ESET", "/Applications/ESET Endpoint Antivirus.app"}, {"Microsoft Defender", "/Applications/Microsoft Defender.app"}} {
		if _, e := os.Stat(u.path(v.path)); e == nil {
			addAV(&p, v.name, core.Unknown, core.Unknown)
			if v.name == "Microsoft Defender" {
				if b, e := u.command(ctx, "/usr/local/bin/mdatp", "health", "--output", "json"); e == nil {
					a := parseMDATP(b)
					addAV(&p, "Microsoft Defender health", a.Running, a.Updated)
				}
			}
		}
	}
	if ctx.Err() != nil {
		p.TTL = 0
	}
	return p
}
func (u UnixProvider) MacInventory(ctx context.Context, software, user bool) core.Inventory {
	inv := core.Inventory{AgentType: "nac", ObservedAt: u.Now(), Software: []core.SoftwareItem{}, Errors: []string{}}
	if software {
		entries, e := os.ReadDir(u.path("/Applications"))
		if e != nil {
			inv.Errors = append(inv.Errors, "Applications inventory unavailable")
		} else {
			inv.SoftwareCollected = true
			for _, entry := range entries {
				if ctx.Err() != nil {
					inv.SoftwareCollected = false
					break
				}
				if filepath.Ext(entry.Name()) != ".app" {
					continue
				}
				m := parseXMLPlist(u.read("/Applications/" + entry.Name() + "/Contents/Info.plist"))
				if m["CFBundleName"] != "" {
					inv.Software = append(inv.Software, core.SoftwareItem{Name: m["CFBundleName"], Version: m["CFBundleShortVersionString"]})
				}
			}
			inv.Software, inv.SoftwareTruncated = NormalizeSoftware(inv.Software)
		}
	}
	if user {
		inv.Errors = append(inv.Errors, "macOS signed-in user provider unavailable")
	}
	return inv
}
