package avvendor

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const kasperskyServiceQuery = "SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service WHERE Name LIKE 'AVP%' OR Name='klnagent'"
const (
	kasperskyWow             = `SOFTWARE\Wow6432Node\KasperskyLab`
	kasperskyNative          = `SOFTWARE\KasperskyLab`
	kasperskyAVWow           = kasperskyWow + `\Components\34\1103\1.0.0.0\Statistics\AVState`
	kasperskyAVNative        = kasperskyNative + `\Components\34\1103\1.0.0.0\Statistics\AVState`
	kasperskyProtectedWow    = kasperskyWow + `\protected`
	kasperskyProtectedNative = kasperskyNative + `\protected`
	kasperskyRTP             = "Protection_RtpState"
	kasperskyBases           = "Protection_BasesDate"
	kasperskyUpdate          = "LastSuccessfulUpdate"
)

var kasperskyDatePattern = regexp.MustCompile(`^\d{2}-\d{2}-\d{4} \d{2}-\d{2}-\d{2}$`)
var kasperskySubkeyPattern = regexp.MustCompile(`^(KES|AVP|KSOS|PURE)`)
var kaspersky = Descriptor{
	ID: "kaspersky", DisplayName: "Kaspersky Endpoint Security / Kaspersky consumer (unverified)",
	Source: "KSC AVState Protection_BasesDate (UTC), Protection_RtpState HKLM SOFTWARE\\Wow6432Node\\KasperskyLab atau SOFTWARE\\KasperskyLab (resmi F1); Win32_Service AVP% PathName Kaspersky (resmi F4, pihak ketiga F6); protected\\KES*|AVP*|KSOS*|PURE*\\Data LastSuccessfulUpdate (pihak ketiga F7/F8, waktu update bukan rilis bases, confidence rendah); belum diverifikasi lab (disetujui Boss)",
	Query:  kasperskyServiceQuery, ParseDate: parseKasperskyDate, ExampleHours: 72, TemplateID: "av-not-updated-kaspersky", Collect: collectKaspersky,
}

func parseKasperskyDate(raw string) (time.Time, bool) {
	if !kasperskyDatePattern.MatchString(raw) {
		return time.Time{}, false
	}
	ts, err := time.Parse("02-01-2006 15-04-05", raw)
	return ts, err == nil
}
func kasperskyTimestamp(raw string) (time.Time, bool) {
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	if n < 1<<32 {
		return time.Unix(int64(n), 0).UTC(), true
	}
	if n >= 1e15 && n/10000000 <= uint64(1<<63-1) {
		seconds := int64(n/10000000) - 11644473600
		return time.Unix(seconds, int64(n%10000000)*100).UTC(), true
	}
	return time.Time{}, false
}
func collectKaspersky(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, serviceErr := s.Enumerate(ctx, kasperskyServiceQuery)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	serviceActive := "unknown"
	if serviceErr == nil {
		for _, row := range rows {
			if !strings.HasPrefix(strings.ToUpper(row["name"]), "AVP") || !strings.Contains(strings.ToLower(row["pathname"]), "kaspersky") {
				continue
			}
			if strings.EqualFold(row["state"], "Running") {
				serviceActive = "enabled"
			} else if strings.EqualFold(row["state"], "Stopped") {
				serviceActive = "disabled"
			}
		}
	}
	// The KSC key can be delayed at boot. Only a missing key permits service fallback.
	missing := true
	for _, key := range []string{kasperskyAVWow, kasperskyAVNative} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryDWORD(ctx, key, kasperskyRTP)
		if r.Status != RegistryNotFound {
			missing = false
		}
		if r.Status == RegistryFound && len(r.Values) == 1 {
			switch r.Values[0] {
			case "4", "5", "6", "7", "8":
				out.Active = "enabled"
			case "1", "2", "9":
				out.Active = "disabled"
			}
		}
		if out.Active != "unknown" {
			break
		}
	}
	if missing {
		out.Active = serviceActive
	}
	// A present but unreadable/invalid primary value must not be replaced by a lower-confidence fallback.
	fallback := true
	for _, key := range []string{kasperskyAVWow, kasperskyAVNative} {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		r := s.RegistryString(ctx, key, kasperskyBases)
		if r.Status == RegistryNotFound {
			continue
		}
		fallback = false
		if r.Status == RegistryFound && len(r.Values) == 1 {
			if ts, ok := parseKasperskyDate(r.Values[0]); ok && !ts.After(checked) {
				out.SignatureLastUpdated = ts
			}
		}
		break
	}
	if fallback {
		for _, root := range []string{kasperskyProtectedWow, kasperskyProtectedNative} {
			if err := ctx.Err(); err != nil {
				return Observation{}, err
			}
			keys := s.RegistrySubkeys(ctx, root)
			if keys.Status != RegistryFound {
				continue
			}
			for _, sub := range keys.Values {
				if !kasperskySubkeyPattern.MatchString(sub) || strings.ContainsAny(sub, `\/`) {
					continue
				}
				key := root + `\` + sub + `\Data`
				for _, read := range []func(context.Context, string, string) RegistryResult{s.RegistryDWORD, s.RegistryQWORD, s.RegistryString} {
					if err := ctx.Err(); err != nil {
						return Observation{}, err
					}
					r := read(ctx, key, kasperskyUpdate)
					if r.Status == RegistryFound && len(r.Values) == 1 {
						if ts, ok := kasperskyTimestamp(r.Values[0]); ok && !ts.After(checked) && ts.After(out.SignatureLastUpdated) {
							out.SignatureLastUpdated = ts
						}
						break
					}
					// Type mismatches may be returned as errors by StdRegProv.
					if r.Status == RegistryDenied {
						break
					}
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	return out, nil
}
