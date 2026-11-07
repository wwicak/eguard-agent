package collector

import (
	"bytes"
	"eguard-nac-agent/core"
	"encoding/xml"
	"io"
	"strings"
)

func parseMacState(kind, s string) core.Tri {
	s = strings.TrimSpace(s)
	pairs := map[string][2]string{"firewall": {"Firewall is enabled. (State = 1)", "Firewall is disabled. (State = 0)"}, "filevault": {"FileVault is On.", "FileVault is Off."}, "gatekeeper": {"assessments enabled", "assessments disabled"}}
	p, ok := pairs[kind]
	if ok {
		if s == p[0] {
			return core.Yes
		}
		if s == p[1] {
			return core.No
		}
	}
	return core.Unknown
}
func colonFields(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if ok {
			m[strings.TrimSpace(k)] = cleanText(v)
		}
	}
	return m
}
func parseSWVers(s string) string {
	m := colonFields(s)
	if m["ProductName"] == "" || m["ProductVersion"] == "" || m["BuildVersion"] == "" {
		return ""
	}
	return m["ProductName"] + "-" + m["ProductVersion"] + "-" + m["BuildVersion"]
}
func parseMacRoute(s string) string { return colonFields(s)["interface"] }
func parseMacDomain(s string) string {
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.TrimSpace(k) == "Active Directory Domain" {
			return cleanText(v)
		}
	}
	return ""
}

// Only flat string values in an XML plist dict are used. Binary or malformed
// plists are skipped, never interpreted as evidence of absence.
func parseXMLPlist(b []byte) map[string]string {
	empty := map[string]string{}
	if bytes.HasPrefix(b, []byte("bplist")) {
		return empty
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	m := map[string]string{}
	key := ""
	root := false
	for {
		t, e := d.Token()
		if e == io.EOF {
			if root {
				return m
			}
			return empty
		}
		if e != nil {
			return empty
		}
		switch x := t.(type) {
		case xml.StartElement:
			if x.Name.Local == "plist" {
				root = true
			}
			if x.Name.Local == "key" {
				if d.DecodeElement(&key, &x) != nil {
					return empty
				}
			}
			if x.Name.Local == "string" {
				var v string
				if d.DecodeElement(&v, &x) != nil {
					return empty
				}
				if key != "" {
					m[key] = cleanText(v)
					key = ""
				}
			}
		}
	}
}
