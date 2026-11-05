package collector

import (
	"context"
	"eguard-nac-agent/avvendor"
	"eguard-nac-agent/core"
	"strings"
	"time"
)

// vendorTimeout bounds one vendor rule, as on the WinRM/DCOM paths;
// vendorBudget bounds all rules together inside one posture collection.
const (
	vendorTimeout = 5 * time.Second
	vendorBudget  = 15 * time.Second
)

// CollectVendorsPrioritized runs the rules for products Windows Security
// Center already reports first, so a slow host cannot exhaust the budget
// before reaching the installed vendor; the remaining rules follow in order.
func CollectVendorsPrioritized(ctx context.Context, s avvendor.Session, now time.Time, products []string) []core.AVVendorEvidence {
	return collectVendorsFrom(ctx, prioritizeVendors(avvendor.All(), products), s, now)
}

func prioritizeVendors(all []avvendor.Descriptor, products []string) []avvendor.Descriptor {
	hit := func(d avvendor.Descriptor) bool {
		id := strings.ToLower(d.ID)
		name := strings.ToLower(d.DisplayName)
		for _, p := range products {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			first := strings.Fields(p)[0]
			if strings.Contains(p, id) || strings.Contains(name, first) || (id == "microsoft-defender" && strings.Contains(p, "defender")) {
				return true
			}
		}
		return false
	}
	first := make([]avvendor.Descriptor, 0, len(all))
	rest := make([]avvendor.Descriptor, 0, len(all))
	for _, d := range all {
		if hit(d) {
			first = append(first, d)
		} else {
			rest = append(rest, d)
		}
	}
	return append(first, rest...)
}

// CollectVendors runs every reviewed vendor rule against a local read-only
// session, with the same acceptance rules as the eGuard WinRM/DCOM
// collectors: a rule error or timeout discards that vendor only, a future
// signature date is rejected, and "absent" is decided here only when every
// read the rule made succeeded and found nothing.
func CollectVendors(ctx context.Context, s avvendor.Session, now time.Time) []core.AVVendorEvidence {
	return collectVendorsFrom(ctx, avvendor.All(), s, now)
}

func collectVendorsFrom(ctx context.Context, descriptors []avvendor.Descriptor, s avvendor.Session, now time.Time) []core.AVVendorEvidence {
	out := []core.AVVendorEvidence{}
	for _, d := range descriptors {
		if d.Collect == nil || ctx.Err() != nil || len(out) >= core.MaxAVVendors {
			continue
		}
		vctx, cancel := context.WithTimeout(ctx, vendorTimeout)
		rec := &absenceSession{inner: s}
		fact, err := d.Collect(vctx, rec, now)
		expired := vctx.Err() != nil
		cancel()
		if err != nil || expired {
			continue
		}
		if fact.Active == "" {
			fact.Active = "unknown"
		}
		if fact.Active != "enabled" && fact.Active != "disabled" && fact.Active != "unknown" {
			continue
		}
		if !fact.SignatureLastUpdated.IsZero() && fact.SignatureLastUpdated.After(now) {
			continue
		}
		empty := fact.Active == "unknown" && fact.SignatureLastUpdated.IsZero()
		switch {
		case empty && rec.cleanEmpty():
			fact.Active = "absent"
		case fact.Absent || empty:
			continue
		}
		if fact.Active == "unknown" {
			// A product whose state could not be read but whose signature
			// date was read is still reported (Unknown running).
		}
		v := core.AVVendorEvidence{ID: d.ID, Active: fact.Active}
		if !fact.SignatureLastUpdated.IsZero() && fact.Active != "absent" {
			t := fact.SignatureLastUpdated.UTC().Round(0)
			v.SignatureLastUpdated = &t
		}
		out = append(out, v)
	}
	return out
}

// absenceSession mirrors the server-side WinRM/DCOM rule: only clean,
// complete negative reads may become "absent".
type absenceSession struct {
	inner avvendor.Session
	reads int
	dirty bool
}

func (s *absenceSession) Enumerate(ctx context.Context, q string) ([]map[string]string, error) {
	s.reads++
	rows, err := s.inner.Enumerate(ctx, q)
	if err != nil || len(rows) != 0 {
		s.dirty = true
	}
	return rows, err
}
func (s *absenceSession) note(r avvendor.RegistryResult) avvendor.RegistryResult {
	s.reads++
	if r.Status != avvendor.RegistryNotFound {
		s.dirty = true
	}
	return r
}
func (s *absenceSession) RegistryString(ctx context.Context, k, n string) avvendor.RegistryResult {
	return s.note(s.inner.RegistryString(ctx, k, n))
}
func (s *absenceSession) RegistryDWORD(ctx context.Context, k, n string) avvendor.RegistryResult {
	return s.note(s.inner.RegistryDWORD(ctx, k, n))
}
func (s *absenceSession) RegistryQWORD(ctx context.Context, k, n string) avvendor.RegistryResult {
	return s.note(s.inner.RegistryQWORD(ctx, k, n))
}
func (s *absenceSession) RegistryBinary(ctx context.Context, k, n string) avvendor.RegistryResult {
	return s.note(s.inner.RegistryBinary(ctx, k, n))
}
func (s *absenceSession) RegistryMultiString(ctx context.Context, k, n string) avvendor.RegistryResult {
	return s.note(s.inner.RegistryMultiString(ctx, k, n))
}
func (s *absenceSession) RegistrySubkeys(ctx context.Context, k string) avvendor.RegistryResult {
	return s.note(s.inner.RegistrySubkeys(ctx, k))
}
func (s *absenceSession) Defender() avvendor.Observation {
	s.dirty = true
	return s.inner.Defender()
}
func (s *absenceSession) cleanEmpty() bool { return s.reads > 0 && !s.dirty }
