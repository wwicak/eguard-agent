package collector

import (
	"context"
	"eguard-nac-agent/avvendor"
	"errors"
	"testing"
	"time"
)

type fakeSession struct {
	rows map[string][]map[string]string
	err  error
	def  avvendor.Observation
}

func (f fakeSession) Enumerate(_ context.Context, q string) ([]map[string]string, error) {
	return f.rows[q], f.err
}
func (fakeSession) RegistryString(context.Context, string, string) avvendor.RegistryResult {
	return avvendor.RegistryResult{Status: avvendor.RegistryNotFound}
}
func (fakeSession) RegistryDWORD(context.Context, string, string) avvendor.RegistryResult {
	return avvendor.RegistryResult{Status: avvendor.RegistryNotFound}
}
func (fakeSession) RegistryQWORD(context.Context, string, string) avvendor.RegistryResult {
	return avvendor.RegistryResult{Status: avvendor.RegistryNotFound}
}
func (fakeSession) RegistryBinary(context.Context, string, string) avvendor.RegistryResult {
	return avvendor.RegistryResult{Status: avvendor.RegistryNotFound}
}
func (fakeSession) RegistryMultiString(context.Context, string, string) avvendor.RegistryResult {
	return avvendor.RegistryResult{Status: avvendor.RegistryNotFound}
}
func (fakeSession) RegistrySubkeys(context.Context, string) avvendor.RegistryResult {
	return avvendor.RegistryResult{Status: avvendor.RegistryNotFound}
}
func (f fakeSession) Defender() avvendor.Observation { return f.def }

func TestCollectVendorsAcceptanceRules(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	date := now.Add(-3 * time.Hour)
	descs := []avvendor.Descriptor{
		{ID: "on", Collect: func(context.Context, avvendor.Session, time.Time) (avvendor.Observation, error) {
			return avvendor.Observation{Active: "enabled", SignatureLastUpdated: date}, nil
		}},
		{ID: "err", Collect: func(context.Context, avvendor.Session, time.Time) (avvendor.Observation, error) {
			return avvendor.Observation{Active: "enabled"}, errors.New("x")
		}},
		{ID: "future", Collect: func(context.Context, avvendor.Session, time.Time) (avvendor.Observation, error) {
			return avvendor.Observation{Active: "enabled", SignatureLastUpdated: now.Add(time.Hour)}, nil
		}},
		{ID: "clean-absent", Collect: func(ctx context.Context, s avvendor.Session, _ time.Time) (avvendor.Observation, error) {
			_, _ = s.Enumerate(ctx, "q-empty")
			return avvendor.Observation{Active: "unknown"}, nil
		}},
		{ID: "dirty-unknown", Collect: func(ctx context.Context, s avvendor.Session, _ time.Time) (avvendor.Observation, error) {
			_, _ = s.Enumerate(ctx, "q-row")
			return avvendor.Observation{Active: "unknown"}, nil
		}},
		{ID: "defender-off", Collect: func(_ context.Context, s avvendor.Session, _ time.Time) (avvendor.Observation, error) {
			return s.Defender(), nil
		}},
	}
	s := fakeSession{rows: map[string][]map[string]string{"q-row": {{"name": "x"}}}, def: avvendor.Observation{Active: "disabled"}}
	got := collectVendorsFrom(context.Background(), descs, s, now)
	want := map[string]string{"on": "enabled", "clean-absent": "absent", "defender-off": "disabled"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for _, v := range got {
		if want[v.ID] != v.Active {
			t.Fatalf("%s=%s", v.ID, v.Active)
		}
		if v.ID == "on" && (v.SignatureLastUpdated == nil || !v.SignatureLastUpdated.Equal(date)) {
			t.Fatal("signature date lost")
		}
		if v.ID != "on" && v.SignatureLastUpdated != nil {
			t.Fatalf("%s must not carry a date", v.ID)
		}
	}
}

func TestCollectVendorsRealRegistryIsBounded(t *testing.T) {
	got := CollectVendors(context.Background(), fakeSession{err: errors.New("wmi down"), def: avvendor.Observation{Active: "unknown"}}, time.Now().UTC())
	for _, v := range got {
		if v.Active == "enabled" || v.Active == "disabled" {
			t.Fatalf("no evidence must not yield running/stopped: %+v", v)
		}
	}
	if len(got) > 64 {
		t.Fatal("unbounded")
	}
}
