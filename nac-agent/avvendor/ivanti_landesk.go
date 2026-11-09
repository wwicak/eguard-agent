package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed read-only root/cimv2 query; inspect only the selected columns.
const ivantiLandeskServiceQuery = "SELECT Name,State,PathName FROM Win32_Service WHERE Name='EPSecurityService'"

var ivantiLandesk = Descriptor{
	ID:          "ivanti-landesk",
	DisplayName: "Ivanti Antivirus / LANDesk Antivirus (unverified)",
	Source:      `Win32_Service EPSecurityService, PathName \Ivanti\ (root/cimv2; resmi Bitdefender BEST F6, bitdefender.com/business/support; pihak ketiga T1, advanceduninstaller.com, untuk klien Ivanti). Running hanya status service, BUKAN bukti RTP aktif; belum diverifikasi lab (disetujui Boss)`,
	Query:       ivantiLandeskServiceQuery, StatusOnly: true, TemplateID: "av-not-active-ivanti-landesk",
	Collect: collectIvantiLandesk,
}

func collectIvantiLandesk(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, ivantiLandeskServiceQuery)
	if err := ctx.Err(); err != nil {
		return out, err
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
	row := rows[0]
	if !strings.EqualFold(row["name"], "EPSecurityService") || !strings.Contains(strings.ToLower(row["pathname"]), `\ivanti\`) {
		return out, nil
	}
	switch strings.ToLower(row["state"]) {
	case "running":
		out.Active = "enabled"
	case "stopped":
		out.Active = "disabled"
	}
	return out, nil
}
