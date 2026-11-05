package avvendor

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Fixed HKLM StdRegProv and root/cimv2 reads; no file content is accessed.
const tmServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='NTRtScan'"
const (
	tmMiscWow    = `SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.`
	tmMiscNative = `SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.`
)

var tmPatternDate = regexp.MustCompile(`^[0-9]{8}$`)

var trendmicro = Descriptor{
	ID: "trendmicro", DisplayName: "Trend Micro Apex One (unverified)",
	Source: "HKLM SOFTWARE\\Wow6432Node\\TrendMicro\\PC-cillinNTCorp\\CurrentVersion\\Misc. / SOFTWARE\\TrendMicro\\PC-cillinNTCorp\\CurrentVersion\\Misc. PatternDate (P1 Nessus, P2 Paessler); Win32_Service NTRtScan (F7 Trend Micro); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss); Running tidak membuktikan proteksi aktif",
	Query:  tmServiceQuery, ParseDate: parseTrendMicroDate, ExampleHours: 72, TemplateID: "av-not-updated-trendmicro",
	Collect: collectTrendMicro,
}

// P2 documents yyyyMMdd but no timezone. Midnight UTC is a convention;
// around the threshold the resulting age can differ by about one day.
func parseTrendMicroDate(raw string) (time.Time, bool) {
	if !tmPatternDate.MatchString(raw) {
		return time.Time{}, false
	}
	date, err := time.Parse("20060102", raw)
	return date, err == nil
}

func collectTrendMicro(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, tmServiceQuery)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if !strings.EqualFold(row["name"], "NTRtScan") {
			continue
		}
		switch {
		case strings.EqualFold(row["state"], "Running"):
			out.Active = "enabled"
		case strings.EqualFold(row["state"], "Stopped"):
			out.Active = "disabled"
		}
	}
	for _, key := range []string{tmMiscWow, tmMiscNative} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryString(ctx, key, "PatternDate")
		if r.Status == RegistryNotFound {
			continue
		}
		// An unreadable or malformed preferred value must not be masked by a fallback.
		if r.Status == RegistryFound && len(r.Values) == 1 {
			date, ok := parseTrendMicroDate(r.Values[0])
			if ok && !date.After(checked) {
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
