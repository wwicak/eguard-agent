package avvendor

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Fixed root/cimv2 reads. C: is the documented default installation, not a
// discovery of alternate ProgramFiles/SystemDrive locations.
const avastServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='avast! Antivirus'"
const avastDirectoryQuery = `SELECT Name,CreationDate,LastModified FROM Win32_Directory WHERE Drive='C:' AND Path='\\Program Files\\AVAST Software\\Avast\\defs\\'`
const avastDefsPrefix = `C:\Program Files\AVAST Software\Avast\defs\`

var avastFolderPattern = regexp.MustCompile(`^[0-9]{8}$`)

var avast = Descriptor{
	ID: "avast", DisplayName: "Avast Antivirus (unverified)",
	Source: "WinRM root/cimv2 Win32_Directory C:\\Program Files\\AVAST Software\\Avast\\defs\\YYMMDDNN (VPS proxy) and Win32_Service avast! Antivirus; lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss); service Running tidak membuktikan proteksi/shield aktif; C: default only, folder terbaru belum tentu dipakai engine; tanggal tanpa zona waktu",
	Query:  avastDirectoryQuery, ParseDate: parseAvastDate, ExampleHours: 72, TemplateID: "av-not-updated-avast",
	Collect: collectAvast,
}

// The folder name encodes a calendar date and release sequence, not a time
// of day. Midnight UTC is a storage convention; age can differ by ±1 day.
func parseAvastDate(raw string) (time.Time, bool) {
	if !avastFolderPattern.MatchString(raw) {
		return time.Time{}, false
	}
	// Parse 20YY explicitly rather than using Go's two-digit year pivot.
	date, err := time.Parse("20060102", "20"+raw[:6])
	return date, err == nil
}

func collectAvast(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	services, err := s.Enumerate(ctx, avastServiceQuery)
	serviceReadOK := err == nil
	if ctx.Err() != nil {
		return Observation{Active: "unknown"}, ctx.Err()
	}
	if err == nil {
		for _, row := range services {
			if !strings.EqualFold(row["name"], "avast! Antivirus") {
				continue
			}
			switch {
			case strings.EqualFold(row["state"], "Running"):
				out.Active = "enabled"
			case strings.EqualFold(row["state"], "Stopped"):
				out.Active = "disabled"
			}
		}
	}
	rows, err := s.Enumerate(ctx, avastDirectoryQuery)
	if ctx.Err() != nil {
		return Observation{Active: "unknown"}, ctx.Err()
	}
	if err == nil {
		for _, row := range rows {
			name := row["name"]
			if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(avastDefsPrefix)) {
				continue
			}
			segment := name[len(avastDefsPrefix):]
			date, ok := parseAvastDate(segment)
			if ok && !date.After(checked) && date.After(out.SignatureLastUpdated) {
				out.SignatureLastUpdated = date
			}
		}
	}
	if serviceReadOK && err == nil && len(services) == 0 && len(rows) == 0 {
		out.Absent = true
	}
	return out, nil
}
