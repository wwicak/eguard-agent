package avvendor

import (
	"context"
	"strings"
	"time"
)

// CylanceSvc is the documented service name for Cylance PROTECT / Aurora Protect.
// Status only: this ML product has no evidenced local signature date.
const cylanceServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='CylanceSvc'"

var cylance = Descriptor{
	ID: "cylance", DisplayName: "Cylance PROTECT / Aurora Protect (unverified)",
	Source: "Win32_Service CylanceSvc (resmi: Arctic Wolf/BlackBerry; pihak ketiga: shouldiremoveit.com); tanpa tanggal definisi lokal (pihak ketiga: fortify24x7.com); belum diverifikasi lab (disetujui Boss)",
	Query:  cylanceServiceQuery, StatusOnly: true, TemplateID: "av-not-active-cylance",
	Collect: collectCylance,
}

func collectCylance(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, cylanceServiceQuery)
	if err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if len(rows) == 0 {
		out.Absent = true
		return out, nil
	}
	for _, row := range rows {
		if !strings.EqualFold(row["name"], "CylanceSvc") {
			continue
		}
		switch {
		case strings.EqualFold(row["state"], "Running"):
			out.Active = "enabled"
		case strings.EqualFold(row["state"], "Stopped"):
			out.Active = "disabled"
		}
	}
	return out, nil
}
