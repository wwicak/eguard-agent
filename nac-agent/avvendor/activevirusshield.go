package avvendor

import (
	"context"
	"strings"
	"time"
)

// Root/cimv2 read-only; AVP is shared with Kaspersky, so the service name
// alone must never be treated as proof of Active Virus Shield.
const activeVirusShieldServiceQuery = "SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service WHERE Name='AVP'"

var activevirusshield = Descriptor{
	ID:          "activevirusshield",
	DisplayName: "AOL Active Virus Shield (EOL 2007) (unverified)",
	Source:      `Win32_Service AVP DisplayName "Active Virus Shield" atau PathName \AOL\Active Virus Shield\; EOL 1 Agustus 2007 (https://en.wikipedia.org/wiki/AOL_Active_Virus_Shield, pihak ketiga); lokasi service https://forums.spybot.info/threads/zlob-dnschanger.15376 (pihak ketiga); belum diverifikasi lab (disetujui Boss)`,
	Query:       activeVirusShieldServiceQuery,
	StatusOnly:  true,
	TemplateID:  "av-not-active-activevirusshield",
	Collect:     collectActiveVirusShield,
}

func collectActiveVirusShield(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, activeVirusShieldServiceQuery)
	if errCtx := ctx.Err(); errCtx != nil {
		return out, errCtx
	}
	if err != nil {
		return out, nil
	}
	if len(rows) == 0 {
		out.Absent = true
		return out, nil
	}
	if len(rows) != 1 {
		return out, nil
	}
	row := rows[0] // Session.Enumerate normalizes WMI property names to lowercase.
	if !strings.EqualFold(row["name"], "AVP") ||
		!(strings.EqualFold(row["displayname"], "Active Virus Shield") || strings.Contains(strings.ToLower(row["pathname"]), `\aol\active virus shield\`)) {
		return out, nil
	}
	switch {
	case strings.EqualFold(row["startmode"], "Disabled"), strings.EqualFold(row["state"], "Stopped"):
		out.Active = "disabled"
	case strings.EqualFold(row["state"], "Running"):
		out.Active = "enabled"
	}
	return out, nil
}
