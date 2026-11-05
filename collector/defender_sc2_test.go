package collector

import (
	"eguard-nac-agent/core"
	"testing"
)

// Observed on real Windows 10 (19045): SecurityCenter2 lists only Defender itself
// ("Windows Defender"), while MSFT_MpComputerStatus reports AM service + realtime
// on and signature age 0. Defender's own SC2 entry is the same product as the
// Defender WMI evidence, not an opaque second vendor, so running/updated are known.
func TestDefenderOwnSecurityCenterEntryIsNotThirdParty(t *testing.T) {
	healthy := DefenderStatus{Present: true, AMRunning: true, Realtime: true, SignaturesAge: 0}
	for _, name := range []string{"Windows Defender", "Microsoft Defender Antivirus"} {
		a := normalizeAV([]AVProduct{{Name: name, State: 0x061100}}, healthy)
		if a.Installed != core.Yes || a.Running != core.Yes || a.Updated != core.Yes {
			t.Fatalf("%s: want yes/yes/yes, got %+v", name, a)
		}
	}
}

// A genuine third-party product must still keep running/updated Unknown, even when
// Defender is healthy (Defender health says nothing about the other vendor).
func TestThirdPartyProductStillOpaque(t *testing.T) {
	healthy := DefenderStatus{Present: true, AMRunning: true, Realtime: true, SignaturesAge: 0}
	a := normalizeAV([]AVProduct{{Name: "Windows Defender", State: 0x061100}, {Name: "Contoso AV", State: 0x041000}}, healthy)
	if a.Running != core.Unknown || a.Updated != core.Unknown {
		t.Fatalf("third-party present: want unknown/unknown, got %+v", a)
	}
	// Lookalike names must not be treated as Defender.
	a = normalizeAV([]AVProduct{{Name: "Windows Defender Pro Cleaner", State: 0}}, healthy)
	if a.Running != core.Unknown {
		t.Fatalf("lookalike vendor treated as Defender: %+v", a)
	}
}
