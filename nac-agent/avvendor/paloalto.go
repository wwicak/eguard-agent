package avvendor

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Fixed root/cimv2 metadata queries; never read file contents.
const paloAltoServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='cyserver' OR Name='CyveraService'"
const paloAltoFileQuery = `SELECT Name,LastModified FROM CIM_DataFile WHERE Drive='C:' AND Path='\\ProgramData\\Cyvera\\LocalSystem\\Download\\content\\'`
const paloAltoNative = `SOFTWARE\Cyvera\Client`
const paloAltoWow = `SOFTWARE\Wow6432Node\Cyvera\Client`

var paloAltoVersion = regexp.MustCompile(`^(\d+)\.(\d+)`)

var paloalto = Descriptor{
	ID: "paloalto", DisplayName: "Palo Alto Cortex XDR / Traps (unverified)",
	Source: "cyserver / CyveraService Win32_Service State (resmi: cortex-docs.paloaltonetworks.com/7.x/7.1-eol/changes-to-default-behavior; docs.paloaltonetworks.com/traps/5-0/traps-agent-admin/traps-agent-for-windows/troubleshoot-traps-for-windows/cytool); HKLM\\SOFTWARE\\Cyvera\\Client Product Version (pihak ketiga: administrator.de/forum/logfile-das-passagen-einer-batch-abfaengt-1731878325.html); C:\\ProgramData\\Cyvera\\LocalSystem\\Download\\content CIM_DataFile.LastModified (lokasi resmi: docs.paloaltonetworks.com/traps/6-1/traps-agent-release-notes/traps-agent-release-information/changes-to-default-behavior.html; makna tanggal pihak ketiga: live.paloaltonetworks.com/t5/cortex-xdr-discussions/any-manual-actions-needed-for-new-certificate-enforcement/m-p/580098); belum diverifikasi lab (disetujui Boss)",
	Query:  paloAltoFileQuery, ParseDate: parseMalwarebytesDate, ExampleHours: 72, TemplateID: "av-not-updated-paloalto", Collect: collectPaloAlto,
}

func collectPaloAlto(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	// The first readable version wins; NotFound alone permits trying the 32-bit view.
	version := ""
	for _, key := range []string{paloAltoNative, paloAltoWow} {
		if err := ctx.Err(); err != nil {
			return Observation{Active: "unknown"}, err
		}
		r := s.RegistryString(ctx, key, "Product Version")
		if r.Status == RegistryNotFound {
			continue
		}
		if r.Status == RegistryFound && len(r.Values) == 1 {
			version = r.Values[0]
		}
		break
	}
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	rows, err := s.Enumerate(ctx, paloAltoServiceQuery)
	if e := ctx.Err(); e != nil {
		return Observation{Active: "unknown"}, e
	}
	if err == nil {
		states := map[string]string{}
		for _, row := range rows {
			name := strings.ToLower(row["name"])
			if name == "cyserver" || name == "cyveraservice" {
				states[name] = row["state"]
			}
		}
		if cy, ok := states["cyserver"]; ok {
			legacy := false
			if match := paloAltoVersion.FindStringSubmatch(version); match != nil {
				major, e1 := strconv.Atoi(match[1])
				minor, e2 := strconv.Atoi(match[2])
				legacy = e1 == nil && e2 == nil && (major < 7 || major == 7 && minor < 1)
			}
			if strings.EqualFold(cy, "Running") {
				if !legacy {
					out.Active = "enabled"
				} else if old, ok := states["cyveraservice"]; ok {
					if strings.EqualFold(old, "Running") {
						out.Active = "enabled"
					} else if strings.EqualFold(old, "Stopped") {
						out.Active = "disabled"
					}
				}
			} else if strings.EqualFold(cy, "Stopped") {
				out.Active = "disabled"
			}
		}
	}
	files, fileErr := s.Enumerate(ctx, paloAltoFileQuery)
	if e := ctx.Err(); e != nil {
		return Observation{Active: "unknown"}, e
	}
	if fileErr == nil {
		const prefix = `c:\programdata\cyvera\localsystem\download\content\`
		for _, row := range files {
			name := strings.ToLower(row["name"])
			if !strings.HasPrefix(name, prefix) || strings.Contains(strings.TrimPrefix(name, prefix), `\`) || len(name) == len(prefix) {
				continue
			}
			ts, ok := parseMalwarebytesDate(row["lastmodified"])
			if ok && !ts.After(checked) && ts.After(out.SignatureLastUpdated) {
				out.SignatureLastUpdated = ts
			}
		}
	}
	return out, nil
}
