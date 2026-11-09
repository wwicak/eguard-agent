package avvendor

import (
	"context"
	"strings"
	"time"
)

// K7RTScan is a third-party-documented service name; query only the columns used.
const k7ServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='K7RTScan'"

var k7 = Descriptor{
	ID: "k7", DisplayName: "K7 Endpoint Security / K7 Total Security / K7 AntiVirus (unverified)",
	Source: "Win32_Service K7RTScan (root/cimv2; pihak ketiga T1, techloris.com / shouldiblockit.com); Running tidak membuktikan RTP aktif; belum diverifikasi lab (disetujui Boss)",
	Query:  k7ServiceQuery, StatusOnly: true, TemplateID: "av-not-active-k7",
	Collect: collectK7,
}

func collectK7(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, k7ServiceQuery)
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
	if len(rows) != 1 || !strings.EqualFold(rows[0]["name"], "K7RTScan") {
		return out, nil
	}
	switch {
	case strings.EqualFold(rows[0]["state"], "Running"):
		out.Active = "enabled"
	case strings.EqualFold(rows[0]["state"], "Stopped"):
		out.Active = "disabled"
	}
	return out, nil
}
