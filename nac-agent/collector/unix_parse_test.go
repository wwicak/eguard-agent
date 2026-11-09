package collector

import (
	"eguard-nac-agent/core"
	"testing"
	"time"
)

func TestUnixTriParsers(t *testing.T) {
	for _, tt := range []struct {
		kind, raw string
		want      core.Tri
	}{
		{"ufw", "Status: active", core.Yes}, {"ufw", "Status: inactive", core.No}, {"ufw", "garbage", core.Unknown},
		{"nft", "table inet filter { chain input { } }", core.Yes}, {"nft", "", core.Unknown}, {"nft", "garbage", core.Unknown},
		{"unit", "active", core.Yes}, {"unit", "inactive", core.No}, {"unit", "garbage", core.Unknown},
	} {
		t.Run(tt.kind+tt.raw, func(t *testing.T) {
			if got := parseUnixState(tt.kind, tt.raw); got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
}
func TestLinuxParsers(t *testing.T) {
	if parseOSRelease("ID=ubuntu\nVERSION_ID=\"24.04\"\n") != "ubuntu-24.04" {
		t.Fatal("os")
	}
	if parseOSRelease("garbage") != "" {
		t.Fatal("garbage os")
	}
	if parseLinuxRoute("Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100000A 0003 0 0 100 00000000") != "eth0" {
		t.Fatal("route")
	}
	if parseLinuxRoute("garbage") != "" {
		t.Fatal("garbage route")
	}
	for _, s := range []string{"domains = example.test", "default_realm = EXAMPLE.TEST", "realm-name: example.test"} {
		if parseLinuxDomain(s) == "" {
			t.Fatal(s)
		}
	}
	if parseLinuxDomain("garbage") != "" {
		t.Fatal("domain")
	}
	now := time.Now()
	if signatureFresh(now.Add(-time.Hour), now, 7*24*time.Hour) != core.Yes || signatureFresh(now.Add(-8*24*time.Hour), now, 7*24*time.Hour) != core.No || signatureFresh(now.Add(time.Hour), now, 7*24*time.Hour) != core.Unknown {
		t.Fatal("freshness")
	}
	for _, tt := range []struct {
		raw          string
		run, updated core.Tri
	}{{`{"real_time_protection_enabled":true,"definitions_status":"up_to_date"}`, core.Yes, core.Yes}, {`{"real_time_protection_enabled":false,"definitions_status":"out_of_date"}`, core.No, core.No}, {`garbage`, core.Unknown, core.Unknown}, {`{}`, core.Unknown, core.Unknown}} {
		a := parseMDATP([]byte(tt.raw))
		if a.Running != tt.run || a.Updated != tt.updated {
			t.Fatalf("mdatp %+v", a)
		}
	}
	if len(parsePackages("pkg\t1\tvendor\npkg\t1\tvendor\ngarbage")) != 1 {
		t.Fatal("inventory")
	}
}
