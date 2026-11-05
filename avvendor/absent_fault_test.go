package avvendor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// faultSession answers every read as "nothing there", except that the
// read number `fail` (1-based, counted across WQL and registry reads)
// fails with the configured failure. fail=0 means no failure.
type faultSession struct {
	fail   int
	denied bool
	n      int
}

func (s *faultSession) hit() bool { s.n++; return s.n == s.fail }
func (s *faultSession) reg() RegistryResult {
	if s.hit() {
		if s.denied {
			return RegistryResult{Status: RegistryDenied}
		}
		return RegistryResult{Status: RegistryError}
	}
	return RegistryResult{Status: RegistryNotFound}
}
func (s *faultSession) Enumerate(context.Context, string) ([]map[string]string, error) {
	if s.hit() {
		return nil, errors.New("wql failure")
	}
	return nil, nil
}
func (s *faultSession) RegistryString(context.Context, string, string) RegistryResult { return s.reg() }
func (s *faultSession) RegistryDWORD(context.Context, string, string) RegistryResult  { return s.reg() }
func (s *faultSession) RegistryQWORD(context.Context, string, string) RegistryResult  { return s.reg() }
func (s *faultSession) RegistryBinary(context.Context, string, string) RegistryResult { return s.reg() }
func (s *faultSession) RegistryMultiString(context.Context, string, string) RegistryResult {
	return s.reg()
}
func (s *faultSession) RegistrySubkeys(context.Context, string) RegistryResult { return s.reg() }
func (s *faultSession) Defender() Observation                                  { return Observation{Active: "unknown"} }

// "No AV at all" policies match on Absent, so for EVERY registered vendor:
// a single failed read anywhere (WQL error, registry Denied or Error) must
// never be reported as a clean absence, and a cancelled context never is.
func TestAbsentNeverReportedOnFailedRead(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for _, d := range All() {
		if d.Collect == nil {
			continue
		}
		clean := &faultSession{}
		obs, err := d.Collect(context.Background(), clean, now)
		reads := clean.n
		if obs.Absent && (err != nil || obs.Active != "unknown" || !obs.SignatureLastUpdated.IsZero()) {
			t.Fatalf("%s: Absent with err=%v active=%q date=%v", d.ID, err, obs.Active, obs.SignatureLastUpdated)
		}
		for i := 1; i <= reads; i++ {
			for _, denied := range []bool{false, true} {
				s := &faultSession{fail: i, denied: denied}
				obs, _ := d.Collect(context.Background(), s, now)
				if obs.Absent {
					t.Errorf("%s: read %d/%d failed (denied=%v) but reported Absent", d.ID, i, reads, denied)
				}
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if obs, _ := d.Collect(ctx, &faultSession{}, now); obs.Absent {
			t.Errorf("%s: cancelled context reported Absent", d.ID)
		}
		t.Log(fmt.Sprintf("%s: reads=%d clean-absent=%v", d.ID, reads, obs.Absent))
	}
}
