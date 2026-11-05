package avvendor

import (
	"context"
	"time"
)

// KB86704 documents native DS content creation date/time in GMT. The
// Wow6432Node path is an unverified best-effort fallback, not proof of install.
const ensDSNative = `SOFTWARE\McAfee\AVSolution\DS\DS`
const ensDSWow = `SOFTWARE\Wow6432Node\McAfee\AVSolution\DS\DS`
const ensDate = "szContentCreationDate"
const ensTime = "szContentCreationTime"

var trellixENS = Descriptor{
	ID: "mcafee-trellix", DisplayName: "Trellix Endpoint Security (AMCore)",
	Source: "Trellix KB86704: HKLM AVSolution\\DS\\DS szContentCreationDate + szContentCreationTime (GMT); AMCore content build time, not endpoint installation/update time. Wow6432Node fallback unverified; date-only uses 00:00 UTC. OAS status unverified (unknown).",
	Query:  "", ParseDate: parseENSDate, ExampleHours: 72, TemplateID: "av-not-updated-mcafee-trellix",
	Collect: collectENS,
}

func parseENSDate(raw string) (time.Time, bool) {
	ts, err := time.Parse("2006-01-02 15:04:05", raw)
	if err != nil || ts.Year() < 1970 {
		return time.Time{}, false
	}
	return ts.UTC(), true
}

func ensScalar(r RegistryResult) (string, bool) {
	if r.Status != RegistryFound || len(r.Values) != 1 {
		return "", false
	}
	return r.Values[0], true
}

func collectENS(ctx context.Context, s Session, now time.Time) (Observation, error) {
	obs := Observation{Active: "unknown"}
	for _, key := range []string{ensDSNative, ensDSWow} {
		if err := ctx.Err(); err != nil {
			return obs, err
		}
		dateResult := s.RegistryString(ctx, key, ensDate)
		if err := ctx.Err(); err != nil {
			return obs, err
		}
		// Only absence allows trying the alternate view. Denial or transport errors
		// cannot establish that a product is absent or that the other view is safe.
		if dateResult.Status == RegistryNotFound {
			continue
		}
		if dateResult.Status != RegistryFound {
			return obs, nil
		}
		date, ok := ensScalar(dateResult)
		if !ok || date == "" {
			return obs, nil
		}
		clockResult := s.RegistryString(ctx, key, ensTime)
		if err := ctx.Err(); err != nil {
			return obs, err
		}
		clock := "00:00:00"
		switch clockResult.Status {
		case RegistryFound:
			var valid bool
			clock, valid = ensScalar(clockResult)
			if !valid {
				return obs, nil
			}
		case RegistryNotFound: // date only: explicitly assume midnight UTC
		default:
			return obs, nil
		}
		ts, valid := parseENSDate(date + " " + clock)
		if valid && !ts.After(now) {
			obs.SignatureLastUpdated = ts
		}
		return obs, nil
	}
	// A missing signature-date location is not proof that ENS is not installed.
	return obs, nil
}
