package avvendor

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Fixed root/cimv2 metadata only. C: and Program Files are installation assumptions.
const avgServiceQuery = "SELECT Name,DisplayName,State FROM Win32_Service WHERE DisplayName='AVG Antivirus' OR Name='avg Antivirus'"
const avgDefsQuery = `SELECT Name,CreationDate,LastModified FROM Win32_Directory WHERE Drive='C:' AND Path='\\Program Files\\AVG\\Antivirus\\defs\\'`

var avgFolderPattern = regexp.MustCompile(`^[0-9]{8}$`)
var avg = Descriptor{
	ID: "avg", DisplayName: "AVG AntiVirus (unverified)",
	Source: "AVG Business Help: AVG Antivirus core service (Win32_Service); community.avg.com T2 / community.avast.com T3: C:\\Program Files\\AVG\\Antivirus\\defs\\YYMMDDNN folder metadata (Win32_Directory); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss). Running bukan bukti File Shield aktif; folder terbaru belum tentu versi aktif; tanggal tanpa zona.",
	Query:  avgDefsQuery, ParseDate: parseAVGDate, ExampleHours: 72, TemplateID: "av-not-updated-avg", Collect: collectAVG,
}

// YYMMDDNN is a calendar date plus release number; midnight UTC is a
// storage convention, not a documented vendor timezone.
func parseAVGDate(raw string) (time.Time, bool) {
	if !avgFolderPattern.MatchString(raw) {
		return time.Time{}, false
	}
	ts, err := time.Parse("20060102", "20"+raw[:6])
	return ts, err == nil
}
func collectAVG(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, avgServiceQuery)
	serviceReadOK := err == nil
	if err == nil {
		for _, row := range rows {
			if !strings.EqualFold(row["name"], "avg Antivirus") && !strings.EqualFold(row["displayname"], "AVG Antivirus") {
				continue
			}
			switch {
			case strings.EqualFold(row["state"], "Stopped"):
				out.Active = "disabled"
			case strings.EqualFold(row["state"], "Running") && out.Active != "disabled":
				out.Active = "enabled"
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	dirs, err := s.Enumerate(ctx, avgDefsQuery)
	if err == nil {
		// The latest name is only a proxy: old folders may remain after updates.
		latest := ""
		for _, row := range dirs {
			// Win32_Directory exposes Name (full path), not CIM_DataFile.FileName.
			name := strings.TrimRight(strings.ReplaceAll(row["name"], `\\`, `\`), `\`)
			if i := strings.LastIndex(name, `\`); i >= 0 {
				name = name[i+1:]
			}
			date, ok := parseAVGDate(name)
			if ok && !date.After(checked) && name > latest {
				latest = name
				out.SignatureLastUpdated = date
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if serviceReadOK && err == nil && len(rows) == 0 && len(dirs) == 0 {
		out.Absent = true
	}
	return out, nil
}
