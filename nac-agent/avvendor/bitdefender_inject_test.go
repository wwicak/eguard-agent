package avvendor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// bitdefenderInjectSession returns hostile registry paths and records every
// WQL statement the collector sends.
type bitdefenderInjectSession struct {
	installPath string
	queries     []string
}

func (s *bitdefenderInjectSession) Enumerate(_ context.Context, q string) ([]map[string]string, error) {
	s.queries = append(s.queries, q)
	if strings.Contains(q, "Win32_Service") {
		return []map[string]string{{"name": "EPSecurityService", "state": "Running", "pathname": `C:\Program Files\Bitdefender\Endpoint Security\EPSecurityService.exe`}}, nil
	}
	return nil, nil
}
func (s *bitdefenderInjectSession) RegistryString(_ context.Context, key, name string) RegistryResult {
	if name == "InstallPath" {
		return RegistryResult{Status: RegistryFound, Values: []string{s.installPath}}
	}
	return RegistryResult{Status: RegistryNotFound}
}
func (s *bitdefenderInjectSession) RegistryDWORD(context.Context, string, string) RegistryResult {
	return RegistryResult{Status: RegistryNotFound}
}
func (s *bitdefenderInjectSession) RegistryQWORD(context.Context, string, string) RegistryResult {
	return RegistryResult{Status: RegistryNotFound}
}
func (s *bitdefenderInjectSession) RegistryBinary(context.Context, string, string) RegistryResult {
	return RegistryResult{Status: RegistryNotFound}
}
func (s *bitdefenderInjectSession) RegistryMultiString(context.Context, string, string) RegistryResult {
	return RegistryResult{Status: RegistryNotFound}
}
func (s *bitdefenderInjectSession) RegistrySubkeys(_ context.Context, key string) RegistryResult {
	if strings.HasSuffix(key, `Endpoint Security`) {
		return RegistryResult{Status: RegistryFound, Values: []string{"{11111111-1111-1111-1111-111111111111}"}}
	}
	return RegistryResult{Status: RegistryNotFound}
}
func (s *bitdefenderInjectSession) Defender() Observation { return Observation{} }

// A registry value is endpoint-controlled input. Any path that could change
// the meaning of the WQL statement must be refused before a query is built.
func TestBitdefenderRegistryPathCannotInjectWQL(t *testing.T) {
	for _, hostile := range []string{
		`C:\x' OR Name LIKE '%`,
		`C:\x" OR 1=1`,
		`C:\Program Files\%`,
		`C:\x;DROP`,
		`\\server\share\Bitdefender`,
		`D:\Bitdefender`,
	} {
		s := &bitdefenderInjectSession{installPath: hostile}
		if _, err := collectBitdefender(context.Background(), s, time.Now()); err != nil {
			t.Fatalf("%q: unexpected error %v", hostile, err)
		}
		for _, q := range s.queries {
			if q == bitdefenderServiceQuery {
				continue
			}
			// Only the reviewed default path or the validated registry path
			// may appear; no fragment of a hostile value may reach WQL.
			for _, bad := range []string{" OR ", "%", ";", `"`, "x'", `\\\\server`, "D:"} {
				if strings.Contains(q, bad) {
					t.Fatalf("%q leaked %q into WQL: %s", hostile, bad, q)
				}
			}
		}
	}
}
