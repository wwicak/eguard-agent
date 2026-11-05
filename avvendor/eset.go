package avvendor

import (
	"context"
	"regexp"
	"strings"
	"time"
)

const esetServiceQuery = "SELECT Name,DisplayName,State,StartMode FROM Win32_Service WHERE Name='ekrn'"
const esetInfoKey = `SOFTWARE\ESET\ESET Security\CurrentVersion\Info`
const esetScannerValue = "ScannerVersion"

var esetScannerPattern = regexp.MustCompile(`^\s*\d+\S*\s*\((\d{8})\)\s*$`)

var eset = Descriptor{
	ID: "eset", DisplayName: "ESET Endpoint (unverified)",
	Source: "WinRM root/cimv2 Win32_Service ekrn (Running bukan bukti RTP/proteksi aktif); HKLM\\SOFTWARE\\ESET\\ESET Security\\CurrentVersion\\Info ScannerVersion (tanggal engine/build, bukan waktu update endpoint); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss)",
	Query:  esetServiceQuery, ParseDate: parseEsetDate, ExampleHours: 72, TemplateID: "av-not-updated-eset",
	Collect: collectEset,
}

// ScannerVersion supplies a calendar day, not a timestamp. Midnight UTC is
// a convention; the age at a 72-hour boundary has approximately ±1 day uncertainty.
func parseEsetDate(raw string) (time.Time, bool) {
	match := esetScannerPattern.FindStringSubmatch(raw)
	if match == nil {
		return time.Time{}, false
	}
	date, err := time.Parse("20060102", match[1])
	return date, err == nil
}

func collectEset(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, esetServiceQuery)
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if err == nil {
		for _, row := range rows {
			if !strings.EqualFold(row["name"], "ekrn") {
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
	r := s.RegistryString(ctx, esetInfoKey, esetScannerValue)
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if r.Status == RegistryFound && len(r.Values) == 1 {
		if date, ok := parseEsetDate(r.Values[0]); ok && !date.After(checked) {
			out.SignatureLastUpdated = date
		}
	}
	return out, nil
}
