//go:build linux || darwin

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (u UnixProvider) LinuxPosture(ctx context.Context, expected string) core.Posture {
	now := u.Now()
	p := Collect(now)
	p.Errors = nil
	fw := ev(core.Unknown, "linux firewall")
	if h, e := os.Hostname(); e == nil {
		p.Hostname = cleanText(h)
	}
	if s := parseOSRelease(string(u.read("/etc/os-release"))); s != "" {
		p.OS = s
	}
	applyRoute(&p, parseLinuxRoute(string(u.read("/proc/net/route"))), "/proc/net/route")
	d := parseLinuxDomain(string(u.read("/etc/sssd/sssd.conf")))
	if d == "" {
		d = parseLinuxDomain(string(u.read("/etc/krb5.conf")))
	}
	if d == "" {
		if b, e := u.command(ctx, "/usr/sbin/realm", "list"); e == nil {
			d = parseLinuxDomain(string(b))
		}
	}
	applyDomain(&p, d, expected, "realm/sssd/krb5 configuration (not live join verification)")
	for _, c := range []struct {
		kind, name string
		args       []string
	}{{"nft", "/usr/sbin/nft", []string{"list", "ruleset"}}, {"ufw", "/usr/sbin/ufw", []string{"status"}}, {"firewalld", "/usr/bin/firewall-cmd", []string{"--state"}}} {
		if b, e := u.command(ctx, c.name, c.args...); e == nil {
			v := parseUnixState(c.kind, string(b))
			if v != core.Unknown {
				fw = ev(v, c.kind)
				break
			}
		}
	}
	p.Firewall = hostFirewall(fw)
	p.Device = &core.DeviceEvidence{SecureBoot: ev(core.Unknown, "efi SecureBoot"), BitlockerOS: ev(core.Unknown, "luks root"), PendingReboot: ev(core.Unknown, "reboot-required")}
	b := u.read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if len(b) == 5 {
		switch b[4] {
		case 0:
			p.Device.SecureBoot.Value = core.No
		case 1:
			p.Device.SecureBoot.Value = core.Yes
		}
	}
	if _, e := os.Stat(u.path("/var/run/reboot-required")); e == nil {
		p.Device.PendingReboot.Value = core.Yes
	} else if os.IsNotExist(e) {
		if i, e := os.Stat(u.path("/var/run")); e == nil && i.IsDir() {
			p.Device.PendingReboot.Value = core.No
		}
	}
	for _, l := range strings.Split(string(u.read("/proc/mounts")), "\n") {
		f := strings.Fields(l)
		if len(f) > 2 && f[1] == "/" {
			dev := filepath.Base(f[0])
			if strings.HasPrefix(f[0], "/dev/mapper/") {
				if target, e := filepath.EvalSymlinks(u.path(f[0])); e == nil {
					dev = filepath.Base(target)
				}
			}
			uuid := strings.TrimSpace(string(u.read("/sys/block/" + dev + "/dm/uuid")))
			if strings.HasPrefix(uuid, "CRYPT-") {
				p.Device.BitlockerOS.Value = core.Yes
			}
		}
	}
	for _, v := range []struct {
		name  string
		units []string
	}{{"ClamAV", []string{"clamav-daemon.service", "clamav-freshclam.service", "clamd.service", "freshclam.service"}}, {"CrowdStrike", []string{"falcon-sensor.service"}}, {"SentinelOne", []string{"sentinelone.service"}}, {"Sophos", []string{"sophos-spl.service"}}, {"ESET", []string{"efs.service"}}, {"Trellix", []string{"mfetpd.service"}}} {
		present := false
		running := core.Unknown
		for _, unit := range v.units {
			for _, dir := range []string{"/lib/systemd/system/", "/etc/systemd/system/"} {
				if _, e := os.Stat(u.path(dir + unit)); e == nil {
					present = true
					if b, e := u.command(ctx, "/usr/bin/systemctl", "is-active", unit); e == nil {
						r := parseUnixState("unit", string(b))
						if running != core.Yes {
							running = r
						}
					}
				}
			}
		}
		if present {
			updated := core.Unknown
			if v.name == "ClamAV" {
				var newest time.Time
				for _, base := range []string{"daily", "main", "bytecode"} {
					for _, ext := range []string{"cvd", "cld"} {
						if i, e := os.Stat(u.path("/var/lib/clamav/" + base + "." + ext)); e == nil && i.ModTime().After(newest) {
							newest = i.ModTime()
						}
					}
				}
				updated = signatureFresh(newest, now, 7*24*time.Hour)
			}
			addAV(&p, v.name, running, updated)
		}
	}
	if b, e := u.command(ctx, "/usr/bin/mdatp", "health", "--output", "json"); e == nil {
		a := parseMDATP(b)
		if a.Installed == core.Yes {
			addAV(&p, "Microsoft Defender", a.Running, a.Updated)
		}
	}
	if ctx.Err() != nil {
		p.TTL = 0
	}
	return p
}
func (u UnixProvider) LinuxInventory(ctx context.Context, software, user bool) core.Inventory {
	inv := core.Inventory{AgentType: "nac", ObservedAt: u.Now(), Software: []core.SoftwareItem{}, Errors: []string{}}
	if software {
		for _, c := range []struct {
			name string
			args []string
		}{{"/usr/bin/dpkg-query", []string{"-W", "-f", "${Package}\t${Version}\t${Maintainer}\n"}}, {"/usr/bin/rpm", []string{"-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"}}} {
			if b, e := u.command(ctx, c.name, c.args...); e == nil {
				inv.Software = parsePackages(string(b))
				inv.SoftwareCollected = true
				inv.SoftwareTruncated = len(inv.Software) == core.MaxSoftwareItems
				break
			}
		}
		if !inv.SoftwareCollected {
			inv.Errors = append(inv.Errors, "software inventory unavailable")
		}
	}
	if user {
		if b, e := u.command(ctx, "/usr/bin/loginctl", "list-sessions", "--no-legend"); e == nil {
			for _, l := range strings.Split(string(b), "\n") {
				f := strings.Fields(l)
				if len(f) >= 3 {
					inv.User = CleanUser(f[2])
					inv.UserCollected = true
					break
				}
			}
		}
	}
	return inv
}
