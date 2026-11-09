package collector

import (
	"eguard-nac-agent/core"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

func parseUnixState(kind, s string) core.Tri {
	s = strings.TrimSpace(s)
	switch kind {
	case "unit":
		if s == "active" {
			return core.Yes
		}
		if s == "inactive" || s == "failed" {
			return core.No
		}
	case "ufw":
		if strings.HasPrefix(s, "Status: active") {
			return core.Yes
		}
		if strings.HasPrefix(s, "Status: inactive") {
			return core.No
		}
	case "firewalld":
		if s == "running" {
			return core.Yes
		}
		if s == "not running" {
			return core.No
		}
	case "nft":
		if strings.Contains(s, "table ") && strings.Contains(s, "{") && strings.Contains(s, "}") {
			return core.Yes
		}
	}
	return core.Unknown
}
func parseOSRelease(s string) string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if ok {
			m[k] = strings.Trim(v, "\"'")
		}
	}
	if m["ID"] == "" || m["VERSION_ID"] == "" {
		return ""
	}
	return cleanText(m["ID"] + "-" + m["VERSION_ID"])
}
func parseLinuxRoute(s string) string {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			flags, e := strconv.ParseUint(f[3], 16, 32)
			if e == nil && flags&1 != 0 {
				return f[0]
			}
		}
	}
	return ""
}
func parseLinuxDomain(s string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		for _, key := range []string{"domains", "default_realm", "realm-name"} {
			if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == key {
				return cleanText(strings.TrimSpace(strings.Split(v, ",")[0]))
			}
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == key {
				return cleanText(v)
			}
		}
	}
	return ""
}
func signatureFresh(mtime, now time.Time, age time.Duration) core.Tri {
	if mtime.IsZero() || mtime.After(now) {
		return core.Unknown
	}
	if now.Sub(mtime) < age {
		return core.Yes
	}
	return core.No
}
func parseMDATP(raw []byte) core.AVEvidence {
	a := core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown, Source: "mdatp"}
	var m struct {
		Realtime    *bool  `json:"real_time_protection_enabled"`
		Definitions string `json:"definitions_status"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return a
	}
	if m.Realtime != nil {
		a.Installed = core.Yes
		a.Running = core.No
		if *m.Realtime {
			a.Running = core.Yes
		}
	}
	switch m.Definitions {
	case "up_to_date":
		a.Updated = core.Yes
	case "out_of_date":
		a.Updated = core.No
	}
	return a
}
func parsePackages(s string) []core.SoftwareItem {
	var out []core.SoftwareItem
	for _, l := range strings.Split(s, "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 3 {
			out = append(out, core.SoftwareItem{Name: f[0], Version: f[1], Publisher: f[2]})
		}
	}
	out, _ = NormalizeSoftware(out)
	return out
}
