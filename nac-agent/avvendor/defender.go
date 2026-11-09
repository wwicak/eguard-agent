package avvendor

import (
	"context"
	"time"
)

// Keep the legacy template ID and exact Defender WQL; existing saved rules
// continue to refer to microsoft-defender.
var defender = Descriptor{
	ID: "microsoft-defender", DisplayName: "Microsoft Defender Antivirus",
	Source:    "Microsoft MSFT_MpComputerStatus.AntivirusSignatureLastUpdated (WinRM)",
	Query:     "SELECT AMRunningMode,AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus",
	ParseDate: parseDefenderDate, ExampleHours: 72, TemplateID: "av-signatures-stale",
	Collect: func(_ context.Context, s Session, _ time.Time) (Observation, error) {
		return s.Defender(), nil // reuse the three existing fixed reads, never query twice
	},
}

func parseDefenderDate(raw string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "20060102150405.000000-070"} {
		if ts, err := time.Parse(layout, raw); err == nil && ts.Year() >= 1970 {
			return ts, true
		}
	}
	return time.Time{}, false
}
