//go:build linux || darwin

package collector

import (
	"context"
	"eguard-nac-agent/core"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnixProviderFixturesAndSignedInventoryGate(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	put := func(p, s string) {
		t.Helper()
		p = filepath.Join(root, p)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	put("etc/os-release", "ID=fixture\nVERSION_ID=1\n")
	put("etc/sssd/sssd.conf", "[sssd]\ndomains = example.test\n")
	put("proc/mounts", "/dev/dm-0 / ext4 rw 0 0\n")
	put("sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-fixture")
	put("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", string([]byte{7, 0, 0, 0, 1}))
	put("var/run/reboot-required", "")
	put("lib/systemd/system/clamav-daemon.service", "fixture")
	put("var/lib/clamav/daily.cld", "fixture")
	var calls []string
	u := UnixProvider{Root: root, Now: func() time.Time { return now }, Run: func(ctx context.Context, n string, a ...string) ([]byte, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
			t.Error("unbounded command")
		}
		key := n + " " + strings.Join(a, " ")
		calls = append(calls, key)
		switch key {
		case "/usr/sbin/nft list ruleset":
			return []byte("table inet filter { }"), nil
		case "/usr/bin/systemctl is-active clamav-daemon.service":
			return []byte("active"), nil
		case "/usr/bin/dpkg-query -W -f ${Package}\t${Version}\t${Maintainer}\n":
			return []byte("fixture\t1\tVendor\n"), nil
		case "/usr/bin/loginctl list-sessions --no-legend":
			return []byte("1 1000 fixture seat0 tty1"), nil
		}
		return nil, errors.New("unavailable")
	}}
	// Ensure the fixture signature is in the past, rather than relying on wallclock resolution.
	sig := filepath.Join(root, "var/lib/clamav/daily.cld")
	if e := os.Chtimes(sig, now.Add(-time.Hour), now.Add(-time.Hour)); e != nil {
		t.Fatal(e)
	}
	p := u.LinuxPosture(context.Background(), "example.test")
	if p.OS != "fixture-1" || p.Domain.Match != core.Yes || p.Device.BitlockerOS.Value != core.Yes || p.Device.SecureBoot.Value != core.Yes || p.Device.PendingReboot.Value != core.Yes || p.Firewall["public"].Value != core.Yes || p.AV.Result() != core.Yes {
		t.Fatalf("%+v", p)
	}
	calls = nil
	inv := u.LinuxInventory(context.Background(), false, false)
	if len(calls) != 0 || inv.SoftwareCollected || inv.UserCollected {
		t.Fatal("unsigned inventory collected")
	}
	inv = u.LinuxInventory(context.Background(), true, true)
	if !inv.SoftwareCollected || !inv.UserCollected || inv.User != "fixture" || len(inv.Software) != 1 {
		t.Fatalf("%+v", inv)
	}
	put("Applications/Fixture.app/Contents/Info.plist", `<plist><dict><key>CFBundleName</key><string>Fixture</string><key>CFBundleShortVersionString</key><string>2</string></dict></plist>`)
	put("Applications/Binary.app/Contents/Info.plist", "bplist00garbage")
	inv = u.MacInventory(context.Background(), true, false)
	if !inv.SoftwareCollected || len(inv.Software) != 1 || inv.Software[0].Version != "2" {
		t.Fatalf("%+v", inv)
	}
}
