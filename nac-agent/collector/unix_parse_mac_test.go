package collector

import (
	"eguard-nac-agent/core"
	"testing"
)

func TestMacParsers(t *testing.T) {
	for _, tt := range []struct {
		kind, s string
		want    core.Tri
	}{{"firewall", "Firewall is enabled. (State = 1)", core.Yes}, {"firewall", "Firewall is disabled. (State = 0)", core.No}, {"filevault", "FileVault is On.", core.Yes}, {"filevault", "FileVault is Off.", core.No}, {"gatekeeper", "assessments enabled", core.Yes}, {"gatekeeper", "assessments disabled", core.No}, {"firewall", "garbage", core.Unknown}, {"filevault", "garbage", core.Unknown}, {"gatekeeper", "garbage", core.Unknown}} {
		if got := parseMacState(tt.kind, tt.s); got != tt.want {
			t.Fatalf("%s %s", tt.kind, got)
		}
	}
	if parseSWVers("ProductName:\tmacOS\nProductVersion:\t15.0\nBuildVersion:\t24A") != "macOS-15.0-24A" {
		t.Fatal("version")
	}
	if parseSWVers("garbage") != "" || parseMacRoute("garbage") != "" || parseMacDomain("garbage") != "" {
		t.Fatal("garbage")
	}
	if parseMacRoute("   interface: en0") != "en0" || parseMacDomain("Active Directory Domain = example.test") != "example.test" {
		t.Fatal("route/domain")
	}
	m := parseXMLPlist([]byte(`<?xml version="1.0"?><plist><dict><key>CFBundleName</key><string>Fixture</string><key>CFBundleShortVersionString</key><string>1.0</string></dict></plist>`))
	if m["CFBundleName"] != "Fixture" {
		t.Fatal(m)
	}
	for _, b := range []string{"garbage", "bplist00xxxx", `<plist><dict><key>Name</key>`} {
		if len(parseXMLPlist([]byte(b))) != 0 {
			t.Fatal("invalid plist")
		}
	}
}
