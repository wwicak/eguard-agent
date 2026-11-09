package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed root/cimv2 metadata queries: no file contents, no caller-controlled WQL.
const clamavServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='clamd' OR Name='freshclam'"
const clamavProgramQuery = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\Program Files\\ClamAV\\database\\daily.cld' OR Name='C:\\Program Files\\ClamAV\\database\\daily.cvd'`
const clamavLegacyQuery = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\ClamAV\\db\\daily.cld' OR Name='C:\\ClamAV\\db\\daily.cvd'`
const clamavWinQuery = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\ProgramData\\.clamwin\\db\\daily.cld' OR Name='C:\\ProgramData\\.clamwin\\db\\daily.cvd'`
const clamavDataKey = `SOFTWARE\ClamAV`
const clamavWowDataKey = `SOFTWARE\Wow6432Node\ClamAV`

var clamav = Descriptor{
	ID: "clamav", DisplayName: "ClamAV / ClamWin (unverified)",
	Source: "HKLM\\SOFTWARE\\ClamAV DataDir (resmi docs.clamav.net / ClamWin Setup.iss), C:\\Program Files\\ClamAV\\database, C:\\ClamAV\\db (resmi), C:\\ProgramData\\.clamwin\\db (resmi Setup.iss; path lama pihak ketiga forums.clamwin.com); CIM_DataFile daily.cld/daily.cvd LastModified adalah waktu freshclam menulis file, bukan tanggal build signature Talos; clamd Win32_Service (resmi); belum diverifikasi lab (disetujui Boss)",
	Query:  clamavServiceQuery, ParseDate: parseClamavDate, ExampleHours: 72, TemplateID: "av-not-updated-clamav", Collect: collectClamav,
}

// CIM_DATETIME is local time with a signed offset in minutes from UTC.
func parseClamavDate(raw string) (time.Time, bool) {
	if len(raw) != 25 || raw[14] != '.' || (raw[21] != '+' && raw[21] != '-') {
		return time.Time{}, false
	}
	for i, c := range raw {
		if i == 14 || i == 21 {
			continue
		}
		if c < '0' || c > '9' {
			return time.Time{}, false
		}
	}
	offset := int(raw[22]-'0')*100 + int(raw[23]-'0')*10 + int(raw[24]-'0')
	if offset > 840 {
		return time.Time{}, false
	}
	if raw[21] == '-' {
		offset = -offset
	}
	ts, err := time.Parse("20060102150405.000000", raw[:21])
	if err != nil || ts.Year() < 1970 {
		return time.Time{}, false
	}
	return ts.Add(-time.Duration(offset) * time.Minute).UTC(), true
}

type clamavLocation struct{ dir, query string }

var clamavLocations = []clamavLocation{
	{`C:\Program Files\ClamAV\database`, clamavProgramQuery},
	{`C:\ClamAV\db`, clamavLegacyQuery},
	{`C:\ProgramData\.clamwin\db`, clamavWinQuery},
}

func collectClamav(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	services, err := s.Enumerate(ctx, clamavServiceQuery)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err == nil {
		seen := false
		for _, row := range services {
			if !strings.EqualFold(row["name"], "clamd") {
				continue
			}
			if seen {
				out.Active = "unknown"
				break
			}
			seen = true
			switch {
			case strings.EqualFold(row["state"], "Running"):
				out.Active = "enabled"
			case strings.EqualFold(row["state"], "Stopped"):
				out.Active = "disabled"
			}
		}
	}
	// Registry is used only to prioritize *reviewed constant* paths. Arbitrary
	// DataDir values cannot be interpolated into WQL under the fixed-query rule.
	locations := make([]clamavLocation, 0, len(clamavLocations))
	for _, key := range []string{clamavDataKey, clamavWowDataKey} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryString(ctx, key, "DataDir")
		if r.Status == RegistryFound && len(r.Values) == 1 {
			for _, loc := range clamavLocations {
				if strings.EqualFold(strings.TrimRight(r.Values[0], `\`), loc.dir) {
					if len(locations) == 0 || locations[0].query != loc.query {
						locations = append(locations, loc)
					}
				}
			}
		}
	}
	for _, loc := range clamavLocations {
		present := false
		for _, v := range locations {
			if v.query == loc.query {
				present = true
			}
		}
		if !present {
			locations = append(locations, loc)
		}
	}
	for _, loc := range locations {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		rows, readErr := s.Enumerate(ctx, loc.query)
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		if readErr != nil {
			continue
		}
		var latest time.Time
		for _, row := range rows {
			name := row["name"]
			if !strings.EqualFold(name, loc.dir+`\daily.cld`) && !strings.EqualFold(name, loc.dir+`\daily.cvd`) {
				continue
			}
			ts, ok := parseClamavDate(row["lastmodified"])
			if ok && !ts.After(checked) && ts.After(latest) {
				latest = ts
			}
		}
		if !latest.IsZero() {
			out.SignatureLastUpdated = latest
			break
		}
	}
	return out, nil
}
