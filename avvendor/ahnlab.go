package avvendor

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Read-only root/cimv2 service state and HKLM engine version; no RTP claim.
const ahnlabServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='V3Svc'"
const (
	ahnlabNative     = `SOFTWARE\AhnLab\ASPack\9.0`
	ahnlabWow        = `SOFTWARE\Wow6432Node\AhnLab\ASPack\9.0`
	ahnlabAscVersion = "AscVersion"
)

var ahnlabDatePattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]{2}$`)

var ahnlab = Descriptor{
	ID: "ahnlab", DisplayName: "AhnLab V3 9.0 (unverified)",
	Source: "Win32_Service V3Svc State: pihak ketiga F6/F8 (Forescout/Advanced Uninstaller); HKLM\\SOFTWARE\\AhnLab\\ASPack\\9.0 AscVersion, fallback Wow6432Node: pihak ketiga F4/F5/F6 (blog/Forescout); format tanggal engine dan ambang 3 hari: resmi F1/F3 (ahnlab.com/help.ahnlab.com); belum diverifikasi lab (disetujui Boss)",
	Query:  ahnlabServiceQuery, ParseDate: parseAhnlabDate, ExampleHours: 72, TemplateID: "av-not-updated-ahnlab", Collect: collectAhnlab,
}

// NN is a release number, not an hour. Date-only convention: 00:00 UTC;
// timezone of the engine date is unverified (uncertainty approximately ±1 day).
func parseAhnlabDate(raw string) (time.Time, bool) {
	if !ahnlabDatePattern.MatchString(raw) {
		return time.Time{}, false
	}
	date, err := time.Parse("2006.01.02", raw[:10])
	return date, err == nil
}

func collectAhnlab(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, ahnlabServiceQuery)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err != nil {
		return out, err
	}
	if len(rows) == 1 && strings.EqualFold(rows[0]["name"], "V3Svc") {
		switch {
		case strings.EqualFold(rows[0]["state"], "Running"):
			out.Active = "enabled"
		case strings.EqualFold(rows[0]["state"], "Stopped"), strings.EqualFold(rows[0]["state"], "Paused"):
			out.Active = "disabled"
		}
	}
	for _, key := range []string{ahnlabNative, ahnlabWow} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryString(ctx, key, ahnlabAscVersion)
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		if r.Status == RegistryNotFound {
			continue
		}
		if r.Status == RegistryFound && len(r.Values) == 1 {
			if date, ok := parseAhnlabDate(r.Values[0]); ok && !date.After(checked) {
				out.SignatureLastUpdated = date
			}
		}
		// Do not override a present but unreadable or malformed native value.
		break
	}
	return out, nil
}
