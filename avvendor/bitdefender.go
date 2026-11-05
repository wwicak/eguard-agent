package avvendor

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const bitdefenderServiceQuery = "SELECT Name,State,PathName FROM Win32_Service WHERE Name='EPSecurityService' OR Name='VSSERV'"
const bitdefenderNative = `SOFTWARE\Bitdefender\Endpoint Security`
const bitdefenderWow = `SOFTWARE\Wow6432Node\Bitdefender\Endpoint Security`
const bitdefenderConsumer = `SOFTWARE\Bitdefender`
const bitdefenderConsumerWow = `SOFTWARE\Wow6432Node\Bitdefender`
const bitdefenderDefault = `C:\Program Files\Bitdefender\Endpoint Security`
const bitdefenderDirSelect = "SELECT Name FROM Win32_Directory WHERE Drive='C:' AND Path='%s'"
const bitdefenderFileSelect = "SELECT Name,LastModified FROM CIM_DataFile WHERE Name='%s'"

var bitdefenderGUID = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)
var bitdefenderFolder = regexp.MustCompile(`(?i)^antivirus_([0-9]+)_([0-9]+)$`)

// Provider-derived components are restricted before embedding in the fixed WQL shapes.
var bitdefenderPath = regexp.MustCompile(`(?i)^C:\\[a-z0-9 ()_.\\-]+$`)
var bitdefenderName = regexp.MustCompile(`(?i)^antivirus[a-z0-9_-]*$`)

var bitdefender = Descriptor{
	ID: "bitdefender", DisplayName: "Bitdefender BEST / Consumer (unverified)",
	Source: "EPSecurityService (resmi F2 bitdefender.com); VSSERV (pihak ketiga F12 shouldiblockit.com); InstallPath/Bitdefender Scan Server (pihak ketiga F8/F9 GLPI); ThreatScanner\\Antivirus_X_Y\\Plugins\\update.txt CIM_DataFile.LastModified proxy (pihak ketiga F6 powershellgallery.com, F8 GLPI; CIM_DATETIME resmi F14 Microsoft); lokasi pihak ketiga, belum diverifikasi lab (disetujui Boss)",
	Query:  bitdefenderServiceQuery, ParseDate: parseMalwarebytesDate, ExampleHours: 72, TemplateID: "av-not-updated-bitdefender", Collect: collectBitdefender,
}

func bitdefenderRead(ctx context.Context, s Session, keys []string, name string) (string, bool) {
	for _, key := range keys {
		if ctx.Err() != nil {
			return "", false
		}
		r := s.RegistryString(ctx, key, name)
		if r.Status == RegistryNotFound {
			continue
		}
		if r.Status == RegistryFound && len(r.Values) == 1 {
			return r.Values[0], true
		}
		return "", false
	}
	return "", false
}
func bitdefenderBase(ctx context.Context, s Session) string {
	for _, key := range []string{bitdefenderNative, bitdefenderWow} {
		r := s.RegistrySubkeys(ctx, key)
		if r.Status == RegistryNotFound {
			continue
		}
		if r.Status != RegistryFound {
			return ""
		}
		for _, sub := range r.Values {
			if !bitdefenderGUID.MatchString(sub) {
				continue
			}
			v, ok := bitdefenderRead(ctx, s, []string{key + `\` + sub + `\Install`}, "InstallPath")
			if ok && bitdefenderPath.MatchString(strings.TrimRight(v, `\`)) {
				return strings.TrimRight(v, `\`)
			}
		}
		return bitdefenderDefault
	}
	return bitdefenderDefault
}
func bitdefenderWQLPath(path string) string { return strings.ReplaceAll(path, `\`, `\\`) }
func collectBitdefender(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, bitdefenderServiceQuery)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err != nil {
		return out, err
	}
	var best, consumer map[string]string
	for _, row := range rows {
		switch {
		case strings.EqualFold(row["name"], "EPSecurityService") && !strings.Contains(strings.ToLower(row["pathname"]), `\ivanti\`):
			if best != nil {
				return out, nil
			}
			best = row
		case strings.EqualFold(row["name"], "VSSERV"):
			if consumer != nil {
				return out, nil
			}
			consumer = row
		}
	}
	var ts string
	if best != nil {
		switch strings.ToLower(best["state"]) {
		case "running":
			out.Active = "enabled"
		case "stopped", "paused":
			out.Active = "disabled"
		}
		base := bitdefenderBase(ctx, s)
		if base != "" {
			ts = base + `\ThreatScanner`
		}
	} else if consumer != nil {
		switch strings.ToLower(consumer["state"]) {
		case "running":
			out.Active = "enabled"
		case "stopped", "paused":
			out.Active = "disabled"
		}
		v, ok := bitdefenderRead(ctx, s, []string{bitdefenderConsumer, bitdefenderConsumerWow}, "Bitdefender Scan Server")
		if ok {
			ts = strings.TrimRight(v, `\`)
		}
	}
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if ts == "" || !bitdefenderPath.MatchString(ts) {
		return out, nil
	}
	dirQuery := fmt.Sprintf(bitdefenderDirSelect, bitdefenderWQLPath(ts[2:]+`\`))
	dirs, err := s.Enumerate(ctx, dirQuery)
	if e := ctx.Err(); e != nil {
		return Observation{Active: "unknown"}, e
	}
	if err != nil {
		return out, nil
	}
	var folder string
	var major, minor uint64
	numeric := false
	for _, row := range dirs {
		name := row["name"]
		if !strings.EqualFold(name[:min(len(name), len(ts)+1)], ts+`\`) || len(name) <= len(ts)+1 {
			continue
		}
		segment := strings.TrimRight(name[len(ts)+1:], `\`)
		if !bitdefenderName.MatchString(segment) {
			continue
		}
		parts := bitdefenderFolder.FindStringSubmatch(segment)
		if parts == nil {
			if folder == "" {
				folder = segment
			}
			continue
		}
		a, ea := strconv.ParseUint(parts[1], 10, 64)
		b, eb := strconv.ParseUint(parts[2], 10, 64)
		if ea != nil || eb != nil {
			continue
		}
		if !numeric || a > major || (a == major && b > minor) {
			folder, major, minor, numeric = segment, a, b, true
		}
	}
	if folder == "" {
		return out, nil
	}
	file := ts + `\` + folder + `\Plugins\update.txt`
	query := fmt.Sprintf(bitdefenderFileSelect, bitdefenderWQLPath(file))
	files, err := s.Enumerate(ctx, query)
	if e := ctx.Err(); e != nil {
		return Observation{Active: "unknown"}, e
	}
	if err != nil {
		return out, nil
	}
	for _, row := range files {
		if !strings.EqualFold(row["name"], file) {
			continue
		}
		date, ok := parseMalwarebytesDate(row["lastmodified"])
		if ok && !date.After(checked) && date.After(out.SignatureLastUpdated) {
			out.SignatureLastUpdated = date
		}
	}
	return out, nil
}
