package avvendor

import (
	"context"
	"strings"
	"time"
)

// RsRavMon is the documented realtime service; no local signature date is established.
// Fixed root/cimv2 read only; no caller-controlled WQL or registry path.
const risingServiceQuery = "SELECT Name,State,StartMode FROM Win32_Service WHERE Name='RsRavMon'"

var rising = Descriptor{
	ID: "rising", DisplayName: "Rising Antivirus (unverified)",
	Source: "WinRM root/cimv2 Win32_Service RsRavMon State/StartMode (lokasi service pihak ketiga: Norton sandbox dan laporan 2007–2019); status service bukan bukti realtime aktif; belum diverifikasi lab (disetujui Boss)",
	Query:  risingServiceQuery, StatusOnly: true, TemplateID: "av-not-active-rising",
	Collect: collectRising,
}

func collectRising(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, risingServiceQuery)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, nil
	} // Denied/provider failure cannot establish service status.
	if len(rows) == 0 {
		out.Absent = true
		return out, nil
	}
	if len(rows) != 1 || !strings.EqualFold(rows[0]["name"], "RsRavMon") {
		return out, nil
	}
	state, mode := rows[0]["state"], rows[0]["startmode"]
	switch {
	case strings.EqualFold(mode, "Disabled"):
		out.Active = "disabled"
	case strings.EqualFold(state, "Running"):
		out.Active = "enabled"
	case state != "":
		out.Active = "disabled"
	}
	return out, nil
}
