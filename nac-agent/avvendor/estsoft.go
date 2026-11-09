package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed read-only root/cimv2 service query; no signature date is available.
const estsoftServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='ALYac_RTSrv'"

var estsoft = Descriptor{
	ID: "estsoft", DisplayName: "ESTsecurity (ESTsoft) ALYac (unverified)",
	Source: "Win32_Service ALYac_RTSrv (root/cimv2; pihak ketiga T1 FRST Malwarebytes forum, T2 AhnLab ASEC, .hermes/plans/vendor-evidence/estsoft.md); Running hanya heuristik service, bukan bukti RTP aktif (toggle UI resmi F7, lokasi status tidak tersedia); belum diverifikasi lab (disetujui Boss)",
	Query:  estsoftServiceQuery, StatusOnly: true, TemplateID: "av-not-active-estsoft",
	Collect: collectEstsoft,
}

func collectEstsoft(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, estsoftServiceQuery)
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
		if !strings.EqualFold(row["name"], "ALYac_RTSrv") {
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
