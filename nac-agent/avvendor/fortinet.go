package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed root/cimv2 metadata reads. Only the documented default 64-bit
// installation path is covered; INSTALLDIR cannot be interpolated into WQL.
const fortinetServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='FA_Scheduler'"
const fortinetFileQuery = `SELECT Name,LastModified FROM CIM_DataFile WHERE Name='C:\\Program Files\\Fortinet\\FortiClient\\vir_sig\\vir_high'`
const fortinetFileName = `C:\Program Files\Fortinet\FortiClient\vir_sig\vir_high`

var fortinet = Descriptor{
	ID: "fortinet", DisplayName: "Fortinet FortiClient (unverified)",
	Source: "C:\\Program Files\\Fortinet\\FortiClient\\vir_sig\\vir_high CIM_DataFile.LastModified (Fortinet KB folder; N-able AVStatus.vbs file/mtime); FA_Scheduler Win32_Service (Fortinet release notes); Running tidak membuktikan proteksi aktif (fmon.exe bisa tidak berjalan); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss)",
	Query:  fortinetFileQuery, ParseDate: parseFalconDate, ExampleHours: 72, TemplateID: "av-not-updated-fortinet",
	Collect: collectFortinet,
}

func collectFortinet(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, fortinetServiceQuery)
	serviceReadOK := err == nil
	if err == nil {
		for _, row := range rows {
			if !strings.EqualFold(row["name"], "FA_Scheduler") {
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
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	files, err := s.Enumerate(ctx, fortinetFileQuery)
	if err == nil {
		for _, row := range files {
			if !strings.EqualFold(row["name"], fortinetFileName) {
				continue
			}
			ts, ok := parseFalconDate(row["lastmodified"])
			if ok && !ts.After(checked) {
				out.SignatureLastUpdated = ts
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if serviceReadOK && err == nil && len(rows) == 0 && len(files) == 0 {
		out.Absent = true
	}
	return out, nil
}
