package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed root/cimv2 read-only query; only selected columns are inspected.
const escanServiceQuery = "SELECT Name,DisplayName,State FROM Win32_Service WHERE DisplayName='eScan Monitor Service' OR Name='eScan Monitor Service'"

var escan = Descriptor{
	ID: "escan", DisplayName: "MicroWorld eScan Anti-Virus / Endpoint Security (unverified)",
	Source: "Win32_Service eScan Monitor Service (root/cimv2; service exists: resmi F9, faqs.escanav.com/?action=artikel&artlang=en&cat=17&id=253; internal name KAVMonitorService: pihak ketiga T2, bleepingcomputer.com/forums/t/193937/i-think-i-have-about-blank/page-2). Running tidak membuktikan RTP aktif atau Pause Protection nonaktif; belum diverifikasi lab (disetujui Boss)",
	Query:  escanServiceQuery, StatusOnly: true, TemplateID: "av-not-active-escan",
	Collect: collectEscan,
}

func collectEscan(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, escanServiceQuery)
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
		if !strings.EqualFold(row["displayname"], "eScan Monitor Service") && !strings.EqualFold(row["name"], "eScan Monitor Service") {
			continue
		}
		if found {
			return Observation{Active: "unknown"}, nil
		}
		found = true
		switch {
		case strings.EqualFold(row["state"], "Running"):
			out.Active = "enabled"
		case row["state"] != "":
			out.Active = "disabled"
		}
	}
	return out, nil
}
