package avvendor

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// T1 (consumer sandbox) reports SigDate but not its type, timezone or meaning.
// Read only the documented candidate; never infer a signature date from other files.
const gdataServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='AVKWCtl'"
const (
	gdataWowStatus    = `SOFTWARE\WOW6432Node\G DATA\AVStatus`
	gdataNativeStatus = `SOFTWARE\G DATA\AVStatus`
)

var gdataISO = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
var gdataDMY = regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}\.[0-9]{4}$`)

var gdata = Descriptor{
	ID: "gdata", DisplayName: "G DATA (unverified)",
	Source: "HKLM SOFTWARE\\WOW6432Node\\G DATA\\AVStatus\\SigDate / SOFTWARE\\G DATA\\AVStatus\\SigDate (T1 softwaretested.com); Win32_Service AVKWCtl (T2 Octoja, T4 shouldiremoveit); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss); Running tidak membuktikan proteksi aktif tanpa status on-access",
	Query:  gdataServiceQuery, ParseDate: parseGDataDate, ExampleHours: 72, TemplateID: "av-not-updated-gdata", Collect: collectGData,
}

// T1 does not establish a timezone. Midnight UTC is a date-only convention,
// not a verified instant of signature update; threshold comparisons may vary by a day.
func parseGDataDate(raw string) (time.Time, bool) {
	var layout string
	switch {
	case gdataISO.MatchString(raw):
		layout = "2006-01-02"
	case gdataDMY.MatchString(raw):
		layout = "02.01.2006"
	default:
		return time.Time{}, false
	}
	d, err := time.Parse(layout, raw)
	return d, err == nil
}
func collectGData(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, gdataServiceQuery)
	if err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if len(rows) == 1 && strings.EqualFold(rows[0]["name"], "AVKWCtl") {
		switch {
		case strings.EqualFold(rows[0]["state"], "Running"):
			out.Active = "enabled"
		case strings.EqualFold(rows[0]["state"], "Stopped"):
			out.Active = "disabled"
		}
	}
	for _, key := range []string{gdataWowStatus, gdataNativeStatus} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryString(ctx, key, "SigDate")
		if r.Status == RegistryNotFound {
			continue
		}
		if r.Status == RegistryFound && len(r.Values) == 1 {
			if d, ok := parseGDataDate(r.Values[0]); ok && !d.After(checked) {
				out.SignatureLastUpdated = d
			}
		}
		break // Never override an unreadable or malformed preferred value.
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	return out, nil
}
