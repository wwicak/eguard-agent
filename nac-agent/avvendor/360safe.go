package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed read-only root/cimv2 query; inspect only selected columns.
const safe360ServiceQuery = "SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service WHERE Name='QHActiveDefense' OR Name='ZhuDongFangYu' OR Name='360rp'"

var safe360 = Descriptor{
	ID: "360safe", DisplayName: "360 Total Security / 360杀毒 / 360安全卫士 (unverified)",
	Source: "Win32_Service root/cimv2: QHActiveDefense (pihak ketiga T1, advanceduninstaller.com), ZhuDongFangYu (pihak ketiga T2, orange-defender.com), 360rp (pihak ketiga T3, hexastrike.com: nama proses, bukan service); fitur Protection (resmi F7, 360totalsecurity.com) tanpa indikator status. Service Running tidak membuktikan RTP aktif; belum diverifikasi lab (disetujui Boss)",
	Query:  safe360ServiceQuery, StatusOnly: true, TemplateID: "av-not-active-360safe",
	Collect: collect360safe,
}

func collect360safe(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, safe360ServiceQuery)
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
	state := ""
	for _, row := range rows {
		name := strings.ToLower(row["name"])
		if name != "qhactivedefense" && name != "zhudongfangyu" && name != "360rp" {
			continue
		}
		if seen[name] {
			return out, nil
		}
		seen[name] = true
		current := strings.ToLower(row["state"])
		if current != "running" && current != "stopped" {
			return out, nil
		}
		if state != "" && state != current {
			return out, nil
		}
		state = current
	}
	switch state {
	case "running":
		out.Active = "enabled"
	case "stopped":
		out.Active = "disabled"
	}
	return out, nil
}
