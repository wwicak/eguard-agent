package avvendor

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Only documented service Names (S1). Running is a service signal, not proof
// that every protection feature is enabled.
const sophosServiceQuery = "SELECT Name,State FROM Win32_Service WHERE Name='Sophos Endpoint Defense' OR Name='Sophos MCS Agent'"
const (
	sophosUpdateWow    = `SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus`
	sophosUpdateNative = `SOFTWARE\Sophos\AutoUpdate\UpdateStatus`
	sophosUpdateValue  = "LastUpdateTime"
)

var sophos = Descriptor{
	ID: "sophos", DisplayName: "Sophos Endpoint (unverified)",
	Source: "Win32_Service Sophos Endpoint Defense / Sophos MCS Agent (resmi S1 support.sophos.com); HKLM SOFTWARE\\WOW6432Node\\Sophos\\AutoUpdate\\UpdateStatus atau SOFTWARE\\Sophos\\AutoUpdate\\UpdateStatus LastUpdateTime epoch UTC (forum pihak ketiga B U1/U2 community.sophos.com; waktu update AutoUpdate, bukan bukti khusus definisi); belum diverifikasi lab (disetujui Boss)",
	Query:  sophosServiceQuery, ParseDate: parseSophosEpoch, ExampleHours: 72, TemplateID: "av-not-updated-sophos",
	Collect: collectSophos,
}

func parseSophosEpoch(raw string) (time.Time, bool) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}

func collectSophos(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, sophosServiceQuery)
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if err == nil {
		states := make(map[string]string, 2)
		valid := true
		for _, row := range rows {
			name := strings.ToLower(row["name"])
			if name != "sophos endpoint defense" && name != "sophos mcs agent" {
				continue
			}
			if _, exists := states[name]; exists {
				valid = false
				break
			}
			states[name] = strings.ToLower(row["state"])
		}
		if valid {
			if states["sophos endpoint defense"] == "stopped" || states["sophos mcs agent"] == "stopped" {
				out.Active = "disabled"
			} else if states["sophos endpoint defense"] == "running" && states["sophos mcs agent"] == "running" {
				out.Active = "enabled"
			}
		}
	}
	// A missing type/key may be tried in the other view. Denied, provider errors,
	// malformed or future values are not evidence that an older fallback is safe.
	for _, key := range []string{sophosUpdateWow, sophosUpdateNative} {
		for _, read := range []func(context.Context, string, string) RegistryResult{s.RegistryDWORD, s.RegistryQWORD} {
			if err := ctx.Err(); err != nil {
				return Observation{Active: "unknown"}, err
			}
			result := read(ctx, key, sophosUpdateValue)
			if err := ctx.Err(); err != nil {
				return Observation{Active: "unknown"}, err
			}
			if result.Status == RegistryNotFound {
				continue
			}
			if result.Status == RegistryFound && len(result.Values) == 1 {
				ts, ok := parseSophosEpoch(result.Values[0])
				if ok && !ts.After(checked) {
					out.SignatureLastUpdated = ts
				}
			}
			return out, nil
		}
	}
	return out, nil
}
