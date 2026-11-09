package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed root/cimv2 metadata reads only; no file content or caller-provided path.
// C: is an assumption; installations elsewhere cannot be assessed.
const vipreServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='SBAMSvc'"
const vipreFileNative = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\Program Files\\VIPRE Business Agent\\Definitions\\DefVer.txt'`
const vipreFileWow = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\Program Files (x86)\\VIPRE Business Agent\\Definitions\\DefVer.txt'`

var vipre = Descriptor{
	ID: "vipre", DisplayName: "VIPRE Business Agent (unverified)",
	Source: "SBAMSvc State (VIPRE F1); C:\\Program Files\\VIPRE Business Agent\\Definitions\\DefVer.txt / C:\\Program Files (x86)\\VIPRE Business Agent\\Definitions\\DefVer.txt LastModified (T1 NinjaOne, T2 advanceduninstaller); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss); Running tidak membuktikan Active Protection aktif; timestamp tulis file bukan tanggal rilis definisi; C: diasumsikan",
	Query:  vipreFileNative, ParseDate: parseVIPREDate, ExampleHours: 72, TemplateID: "av-not-updated-vipre",
	Collect: collectVIPRE,
}

// CIM_DATETIME is local endpoint time with a signed UTC offset in minutes.
func parseVIPREDate(raw string) (time.Time, bool) {
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

func collectVIPRE(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, vipreServiceQuery)
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if err == nil && len(rows) == 1 && strings.EqualFold(rows[0]["name"], "SBAMSvc") {
		switch {
		case strings.EqualFold(rows[0]["state"], "Running"):
			out.Active = "enabled"
		case strings.EqualFold(rows[0]["state"], "Stopped"):
			out.Active = "disabled"
		}
	}
	for _, entry := range []struct{ query, path string }{
		{vipreFileNative, `C:\Program Files\VIPRE Business Agent\Definitions\DefVer.txt`},
		{vipreFileWow, `C:\Program Files (x86)\VIPRE Business Agent\Definitions\DefVer.txt`},
	} {
		if err := ctx.Err(); err != nil {
			return Observation{Active: "unknown"}, err
		}
		files, fileErr := s.Enumerate(ctx, entry.query)
		if err := ctx.Err(); err != nil {
			return Observation{Active: "unknown"}, err
		}
		// Provider failure is not proof of absence; do not override with fallback.
		if fileErr != nil {
			break
		}
		if len(files) == 0 {
			continue
		}
		if len(files) == 1 && strings.EqualFold(strings.ReplaceAll(files[0]["name"], `\\`, `\`), entry.path) {
			ts, ok := parseVIPREDate(files[0]["lastmodified"])
			if ok && !ts.After(checked) {
				out.SignatureLastUpdated = ts
			}
		}
		break
	}
	return out, nil
}
