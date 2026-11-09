package avvendor

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// CBC cloud sensor only. Metadata reads do not open signature files.
// Data_2 is a candidate not confirmed by the Broadcom example (Data_1).
const cbServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='CbDefense'"
const cbData1Query = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\Program Files\\Confer\\scanner\\Data_1\\aevdf.dat'`
const cbData2Query = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\Program Files\\Confer\\scanner\\Data_2\\aevdf.dat'`
const cbDefenseKey = `SYSTEM\CurrentControlSet\Services\CbDefense`

var carbonblack = Descriptor{
	ID: "carbonblack", DisplayName: "Carbon Black Cloud sensor (unverified)",
	Source: "Broadcom resmi KB 285610: HKLM SYSTEM\\CurrentControlSet\\Services\\CbDefense ServiceRunning/Passthru, CbDefense service; Broadcom resmi KB 284872: C:\\Program Files\\Confer\\scanner\\Data_1\\aevdf.dat; Data_2 kandidat belum terbukti; CIM_DataFile.LastModified adalah proxy signature lokal, bukan tanggal VDF resmi, hanya relevan bila Local Scanner aktif (KB 291481), lokasi 4.2+ belum terbukti; belum diverifikasi lab (disetujui Boss)",
	Query:  cbData1Query, ParseDate: parseCBDate, ExampleHours: 72, TemplateID: "av-not-updated-carbonblack",
	Collect: collectCarbonblack,
}

// CIM datetime with offset minutes from UTC.
func parseCBDate(raw string) (time.Time, bool) {
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
func collectCarbonblack(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	services, err := s.Enumerate(ctx, cbServiceQuery)
	if e := ctx.Err(); e != nil {
		return Observation{Active: "unknown"}, e
	}
	present := false
	if err == nil && len(services) == 1 && strings.EqualFold(services[0]["name"], "CbDefense") {
		present = true
		switch {
		case strings.EqualFold(services[0]["state"], "Stopped"):
			out.Active = "disabled"
		case strings.EqualFold(services[0]["state"], "Running"):
			running := s.RegistryDWORD(ctx, cbDefenseKey, "ServiceRunning")
			if e := ctx.Err(); e != nil {
				return Observation{Active: "unknown"}, e
			}
			bypass := s.RegistryDWORD(ctx, cbDefenseKey, "Passthru")
			if e := ctx.Err(); e != nil {
				return Observation{Active: "unknown"}, e
			}
			bypassKnown := bypass.Status == RegistryNotFound
			bypassValue := uint64(0)
			if bypass.Status == RegistryFound && len(bypass.Values) == 1 {
				var parseErr error
				bypassValue, parseErr = strconv.ParseUint(bypass.Values[0], 10, 32)
				bypassKnown = parseErr == nil
			}
			if bypassKnown && bypassValue == 1 {
				out.Active = "disabled"
			} else if running.Status == RegistryFound && len(running.Values) == 1 && running.Values[0] == "1" && bypassKnown {
				out.Active = "enabled"
			}
		}
	}
	// A missing service is not proof that the product is installed; do not
	// attach orphaned file timestamps to an absent product.
	if !present {
		return out, nil
	}
	for _, candidate := range []struct{ query, name string }{{cbData1Query, `C:\Program Files\Confer\scanner\Data_1\aevdf.dat`}, {cbData2Query, `C:\Program Files\Confer\scanner\Data_2\aevdf.dat`}} {
		rows, readErr := s.Enumerate(ctx, candidate.query)
		if e := ctx.Err(); e != nil {
			return Observation{Active: "unknown"}, e
		}
		if readErr != nil {
			continue
		}
		for _, row := range rows {
			if !strings.EqualFold(row["name"], candidate.name) {
				continue
			}
			ts, ok := parseCBDate(row["lastmodified"])
			if ok && !ts.After(checked) && ts.After(out.SignatureLastUpdated) {
				out.SignatureLastUpdated = ts
			}
		}
	}
	return out, nil
}
