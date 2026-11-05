package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed read-only root/cimv2 query; service names are third-party observations.
const aviraServiceQuery = "SELECT Name,State,StartMode,PathName FROM Win32_Service WHERE Name='AviraSecurity' OR Name='EndpointProtectionService' OR Name='AntiVirService'"

var avira = Descriptor{
	ID: "avira", DisplayName: "Avira Security / Endpoint Protection / AntiVir (unverified)",
	Source: "Win32_Service AviraSecurity, EndpointProtectionService (https://bleepingcomputer.com/forums/t/809212/virus-suspected?view=getlastpost, pihak ketiga P1); AntiVirService (https://shouldiblockit.com/avguard.exe-49492.aspx, pihak ketiga P3); service Running tidak membuktikan RTP aktif (https://support.avira.com/hc/en-us/articles/360000850585, resmi 2a; http://avira.helpmax.net/en/help-center/control-center/view/status, pihak ketiga 2c); belum diverifikasi lab (disetujui Boss)",
	Query:  aviraServiceQuery, StatusOnly: true, TemplateID: "av-not-active-avira", Collect: collectAvira,
}

func collectAvira(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, aviraServiceQuery)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, nil
	}
	if len(rows) == 0 {
		out.Absent = true
		return out, nil
	}
	seen := make(map[string]bool, 3)
	running, stopped := false, false
	for _, row := range rows {
		name := strings.ToLower(row["name"])
		if name != "avirasecurity" && name != "endpointprotectionservice" && name != "antivirservice" {
			continue
		}
		if seen[name] {
			return out, nil
		}
		seen[name] = true
		switch {
		case strings.EqualFold(row["startmode"], "Disabled"), strings.EqualFold(row["state"], "Stopped"):
			stopped = true
		case strings.EqualFold(row["state"], "Running"):
			running = true
		default:
			return out, nil
		}
	}
	if running && !stopped {
		out.Active = "enabled"
	}
	if stopped && !running {
		out.Active = "disabled"
	}
	return out, nil
}
