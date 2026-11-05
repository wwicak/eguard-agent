package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed read-only root/cimv2 query; the service name is third-party evidence.
const hauriServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='hVrMalSvc'"

var hauri = Descriptor{
	ID: "hauri", DisplayName: "Hauri ViRobot (unverified)",
	Source: "Win32_Service hVrMalSvc (root/cimv2; pihak ketiga T1/T2 advanceduninstaller.com, T3 shouldiremoveit.com, T4 processchecker.com; service Running bukan bukti RTP aktif); belum diverifikasi lab (disetujui Boss)",
	Query:  hauriServiceQuery, StatusOnly: true, TemplateID: "av-not-active-hauri",
	Collect: collectHauri,
}

func collectHauri(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, hauriServiceQuery)
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
	found := false
	for _, row := range rows {
		if !strings.EqualFold(row["name"], "hVrMalSvc") {
			continue
		}
		if found {
			return Observation{Active: "unknown"}, nil
		}
		found = true
		switch strings.ToLower(row["state"]) {
		case "running":
			out.Active = "enabled"
		case "stopped":
			out.Active = "disabled"
		}
	}
	return out, nil
}
