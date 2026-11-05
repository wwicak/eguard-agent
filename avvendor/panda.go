package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed root/cimv2 reads. C: is an assumption; no file contents are read.
const pandaServiceQuery = "SELECT Name,State,StartMode FROM Win32_Service WHERE Name='NanoServiceMain' OR Name='PSUAService' OR Name='PandaAetherAgent'"
const pandaFileQuery = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\ProgramData\\Panda Security\\Security Protection\\NanoRepository.bin'`
const pandaFileName = `C:\ProgramData\Panda Security\Security Protection\NanoRepository.bin`
const (
	pandaNative = `SOFTWARE\Panda Security\AdminIE\Protections`
	pandaWow    = `SOFTWARE\Wow6432Node\Panda Security\AdminIE\Protections`
)

var panda = Descriptor{
	ID: "panda", DisplayName: "WatchGuard Endpoint Security / Panda (unverified)",
	Source: "NanoRepository.bin CIM_DataFile.LastModified (T3 StackOverflow, lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss)); WAC HKLM AdminIE\\Protections (F11); NanoServiceMain Win32_Service (F6/F8); Running hanya status service, bukan bukti RTP/proteksi aktif; timestamp bukan tanggal signature terverifikasi; asumsi drive C:",
	Query:  pandaFileQuery, ParseDate: parseFalconDate, ExampleHours: 72, TemplateID: "av-not-updated-panda", Collect: collectPanda,
}

func collectPanda(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	installed := false
	for _, key := range []string{pandaNative, pandaWow} {
		r := s.RegistryString(ctx, key, "WAC")
		if err := ctx.Err(); err != nil {
			return Observation{Active: "unknown"}, err
		}
		if r.Status == RegistryFound && len(r.Values) == 1 && strings.TrimSpace(r.Values[0]) != "" {
			installed = true
		}
	}
	if !installed {
		return out, nil
	}
	rows, err := s.Enumerate(ctx, pandaServiceQuery)
	if e := ctx.Err(); e != nil {
		return Observation{Active: "unknown"}, e
	}
	if err == nil {
		for _, row := range rows {
			if !strings.EqualFold(row["name"], "NanoServiceMain") {
				continue
			}
			switch {
			case strings.EqualFold(row["startmode"], "Disabled"), strings.EqualFold(row["state"], "Stopped"):
				out.Active = "disabled"
			case strings.EqualFold(row["state"], "Running"):
				out.Active = "enabled"
			}
		}
	}
	files, fileErr := s.Enumerate(ctx, pandaFileQuery)
	if e := ctx.Err(); e != nil {
		return Observation{Active: "unknown"}, e
	}
	if fileErr == nil {
		for _, row := range files {
			if !strings.EqualFold(row["name"], pandaFileName) {
				continue
			}
			if ts, ok := parseFalconDate(row["lastmodified"]); ok && !ts.After(checked) {
				out.SignatureLastUpdated = ts
			}
		}
	}
	return out, nil
}
