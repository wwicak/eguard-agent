package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed root/cimv2 reads. C: is a limitation on installations with another
// SystemDrive; no caller input may be interpolated into WQL.
const falconServiceQuery = "SELECT Name, State, StartMode FROM Win32_Service WHERE Name='CSFalconService' OR Name='csagent'"
const falconFileQuery = `SELECT Name, FileName, LastModified, FileSize FROM CIM_DataFile WHERE Drive='C:' AND Path='\\Windows\\System32\\drivers\\CrowdStrike\\' AND Extension='sys' AND FileName LIKE 'C-%'`

var crowdstrike = Descriptor{
	ID: "crowdstrike", DisplayName: "CrowdStrike Falcon (content last received)",
	Source: "CrowdStrike Channel File LastModified (WinRM root/cimv2); proxy for content last received, not a signature timestamp; C: SystemDrive assumption",
	Query:  falconFileQuery, ParseDate: parseFalconDate, ExampleHours: 24, TemplateID: "av-not-updated-crowdstrike",
	Collect: collectFalcon,
}

// CIM datetime: YYYYMMDDhhmmss.ffffff±mmm, offset in minutes from UTC.
func parseFalconDate(raw string) (time.Time, bool) {
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

func collectFalcon(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	services, err := s.Enumerate(ctx, falconServiceQuery)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err == nil {
		found := false
		running := false
		driverStopped := false
		for _, row := range services {
			switch {
			case strings.EqualFold(row["name"], "CSFalconService"):
				found = true
				if strings.EqualFold(row["state"], "Running") {
					running = true
				} else if strings.EqualFold(row["state"], "Stopped") || strings.EqualFold(row["startmode"], "Disabled") {
					out.Active = "disabled"
				}
			case strings.EqualFold(row["name"], "csagent"):
				if strings.EqualFold(row["state"], "Stopped") || strings.EqualFold(row["startmode"], "Disabled") {
					driverStopped = true
				}
			}
		}
		if found && out.Active != "disabled" {
			if driverStopped {
				out.Active = "disabled"
			} else if running {
				out.Active = "enabled"
			}
		}
	}
	files, fileErr := s.Enumerate(ctx, falconFileQuery)
	if ctx.Err() != nil {
		return Observation{Active: "unknown"}, ctx.Err()
	}
	if fileErr == nil {
		for _, row := range files {
			// Defense in depth: do not trust a malformed provider row outside the WQL filter.
			if !strings.HasPrefix(strings.ToUpper(row["filename"]), "C-") {
				continue
			}
			ts, ok := parseFalconDate(row["lastmodified"])
			if ok && !ts.After(checked) && ts.After(out.SignatureLastUpdated) {
				out.SignatureLastUpdated = ts
			}
		}
	}
	if err == nil && fileErr == nil && len(services) == 0 && len(files) == 0 {
		out.Absent = true
	}
	return out, nil
}
