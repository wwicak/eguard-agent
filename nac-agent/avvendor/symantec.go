package avvendor

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// The only service whose presence/status is supported for SEP 14.x by the evidence.
const sepServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='SepMasterService'"
const (
	sepNative       = `SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\`
	sepWow          = `SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\`
	sepPublicNative = sepNative + `Public-Opstate`
	sepPublicWow    = sepWow + `Public-Opstate`
	sepSharedNative = sepNative + `SharedDefs\SDSDefs`
	sepSharedWow    = sepWow + `SharedDefs\SDSDefs`
	sepLegacyNative = sepNative + `SharedDefs`
	sepLegacyWow    = sepWow + `SharedDefs`
)

var sepPublicPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
var sepFolderPattern = regexp.MustCompile(`^[0-9]{8}\.[0-9]+$`)

var symantec = Descriptor{
	ID: "symantec", DisplayName: "Symantec Endpoint Protection",
	Source: "Broadcom SEP 14.x Public-Opstate LatestVirusDefsDate / SharedDefs SRTSP and SepMasterService (WinRM)",
	Query:  sepServiceQuery, ParseDate: parseSEPDate, ExampleHours: 72, TemplateID: "av-not-updated-symantec",
	Collect: collectSymantec,
}

// Date-only values have no documented timezone. Store midnight UTC as a
// convention; age near the threshold is uncertain by approximately ±1 day.
func parseSEPDate(raw string) (time.Time, bool) {
	if !sepPublicPattern.MatchString(raw) {
		return time.Time{}, false
	}
	d, err := time.Parse("2006-01-02", raw)
	return d, err == nil
}
func parseSEPFolder(raw string) (time.Time, bool) {
	segment := raw[strings.LastIndex(raw, `\`)+1:]
	if !sepFolderPattern.MatchString(segment) {
		return time.Time{}, false
	}
	d, err := time.Parse("20060102", segment[:8])
	return d, err == nil
}
func collectSymantec(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, sepServiceQuery)
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if !strings.EqualFold(row["name"], "SepMasterService") {
			continue
		}
		switch {
		case strings.EqualFold(row["state"], "Running"):
			out.Active = "enabled"
		case strings.EqualFold(row["state"], "Stopped"):
			out.Active = "disabled"
		}
	}
	for _, entry := range []struct {
		key, name string
		parse     func(string) (time.Time, bool)
	}{
		{sepPublicNative, "LatestVirusDefsDate", parseSEPDate},
		{sepPublicWow, "LatestVirusDefsDate", parseSEPDate},
		{sepSharedNative, "SRTSP", parseSEPFolder},
		{sepSharedWow, "SRTSP", parseSEPFolder},
		{sepLegacyNative, "SRTSP", parseSEPFolder},
		{sepLegacyWow, "SRTSP", parseSEPFolder},
	} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryString(ctx, entry.key, entry.name)
		// A found but malformed/unsupported value must not be guessed as a DWORD.
		if r.Status == RegistryNotFound {
			continue
		}
		// A present but unreadable/unsupported value cannot be safely
		// overridden by a possibly older fallback definition.
		if r.Status != RegistryFound || len(r.Values) != 1 {
			break
		}
		date, ok := entry.parse(r.Values[0])
		if ok && !date.After(checked) {
			out.SignatureLastUpdated = date
		}
		break
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	return out, nil
}
