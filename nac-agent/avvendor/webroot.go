package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed read-only root/cimv2 query. Only selected columns are inspected.
const webrootServiceQuery = "SELECT Name,State,StartMode FROM Win32_Service WHERE Name='WRSVC' OR Name='WRCoreService' OR Name='WRSkyClient'"

var webroot = Descriptor{
	ID: "webroot", DisplayName: "Webroot SecureAnywhere / OpenText Core Endpoint Protection (unverified)",
	Source: "Win32_Service WRSVC, WRCoreService, WRSkyClient (root/cimv2; present and running: resmi F1, answers.webroot.com); Core service context: pihak ketiga F2, community.webroot.com; cloud tanpa definisi lokal: resmi F10, webroot.com; belum diverifikasi lab (disetujui Boss)",
	Query:  webrootServiceQuery, StatusOnly: true, TemplateID: "av-not-active-webroot",
	Collect: collectWebroot,
}

func collectWebroot(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, webrootServiceQuery)
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
	states := make(map[string]string, 3)
	for _, row := range rows {
		name := strings.ToLower(row["name"])
		if name != "wrsvc" && name != "wrcoreservice" && name != "wrskyclient" {
			continue
		}
		if _, exists := states[name]; exists {
			return out, nil
		}
		state := strings.ToLower(row["state"])
		if strings.EqualFold(row["startmode"], "Disabled") {
			state = "stopped"
		}
		states[name] = state
	}
	for _, name := range []string{"wrsvc", "wrcoreservice", "wrskyclient"} {
		if states[name] == "stopped" {
			out.Active = "disabled"
			return out, nil
		}
	}
	if len(states) == 3 && states["wrsvc"] == "running" && states["wrcoreservice"] == "running" && states["wrskyclient"] == "running" {
		out.Active = "enabled"
	}
	return out, nil
}
