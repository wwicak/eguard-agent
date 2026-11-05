package avvendor

import (
	"context"
	"strings"
	"time"
)

const fsecureServiceQuery = "SELECT Name,State,StartMode FROM Win32_Service WHERE Name='fsulhoster' OR Name='fsulprothoster' OR Name='wsulavprothoster' OR Name='fshoster' OR Name='fsnethoster'"
const fsecureWow = `SOFTWARE\Wow6432Node\F-Secure\Monitoring\AntiVirus`
const fsecureNative = `SOFTWARE\F-Secure\Monitoring\AntiVirus`

var fsecure = Descriptor{
	ID: "fsecure", DisplayName: "F-Secure / WithSecure (unverified)",
	Source: "HKLM SOFTWARE\\Wow6432Node\\F-Secure\\Monitoring\\AntiVirus and SOFTWARE\\F-Secure\\Monitoring\\AntiVirus AvDefinitionsUpdateTime (subkey/value kandidat inferensi mirror WMI admin guide WithSecure; format CIM admin guide / format alternatif forum vendor V4); root/cimv2 Win32_Service fsulhoster (KB resmi F8); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss); Running tidak membuktikan RTP aktif",
	Query:  fsecureServiceQuery, ParseDate: parseFSecureDate, ExampleHours: 72, TemplateID: "av-not-updated-fsecure", Collect: collectFSecure,
}

// The mirror's value and format are candidates, not documented vendor guarantees.
// CIM offset is minutes; forum output uses the second layout.
func parseFSecureDate(raw string) (time.Time, bool) {
	if len(raw) == 25 && raw[14] == '.' && (raw[21] == '+' || raw[21] == '-') {
		return parseFalconDate(raw)
	}
	if len(raw) != 23 || raw[19] != '+' && raw[19] != '-' {
		return time.Time{}, false
	}
	for i, c := range raw {
		switch i {
		case 4, 7, 10, 13, 16, 19:
			continue
		}
		if c < '0' || c > '9' {
			return time.Time{}, false
		}
	}
	if raw[4] != '-' || raw[7] != '-' || raw[10] != ' ' || raw[13] != ':' || raw[16] != ':' {
		return time.Time{}, false
	}
	offset := int(raw[20]-'0')*100 + int(raw[21]-'0')*10 + int(raw[22]-'0')
	if offset > 840 {
		return time.Time{}, false
	}
	if raw[19] == '-' {
		offset = -offset
	}
	ts, err := time.Parse("2006-01-02 15:04:05", raw[:19])
	if err != nil || ts.Year() < 1970 {
		return time.Time{}, false
	}
	return ts.Add(-time.Duration(offset) * time.Minute).UTC(), true
}
func collectFSecure(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, fsecureServiceQuery)
	if ctx.Err() != nil {
		return Observation{}, ctx.Err()
	}
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if strings.EqualFold(row["name"], "fsulhoster") {
			switch {
			case strings.EqualFold(row["state"], "Running"):
				out.Active = "enabled"
			case strings.EqualFold(row["state"], "Stopped"):
				out.Active = "disabled"
			}
			break
		}
	}
	for _, key := range []string{fsecureWow, fsecureNative} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryString(ctx, key, "AvDefinitionsUpdateTime")
		if r.Status == RegistryNotFound {
			continue
		}
		if r.Status == RegistryFound && len(r.Values) == 1 {
			if date, ok := parseFSecureDate(r.Values[0]); ok && !date.After(checked) {
				out.SignatureLastUpdated = date
			}
		}
		break
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	return out, nil
}
