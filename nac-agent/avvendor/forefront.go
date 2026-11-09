package avvendor

import (
	"context"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

const forefrontServiceQuery = "SELECT Name,State,StartMode FROM Win32_Service WHERE Name='FCSAM' OR Name='MsMpSvc'"
const (
	forefrontFCS    = `SOFTWARE\Microsoft\Microsoft Forefront\Client Security\1.0\AM\Signature Updates`
	forefrontMAR    = `SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates`
	forefrontMARoot = `SOFTWARE\Microsoft\Microsoft Antimalware`
)

var forefront = Descriptor{
	ID: "forefront", DisplayName: "Microsoft Forefront / System Center Endpoint Protection (unverified)",
	Source: "FCS AVSignatureApplied FILETIME at HKLM\\" + forefrontFCS + " (resmi Microsoft F6/F7); FEP/SCEP SignaturesLastUpdated / AVSignatureApplied FILETIME at HKLM\\" + forefrontMAR + " (key resmi F9, value pihak ketiga T1–T3); FCSAM / MsMpSvc Win32_Service dan EndOfLifeState (resmi F11/F12/F14); belum diverifikasi lab (disetujui Boss). MsMpSvc dan Microsoft Antimalware key juga dipakai MSE/Azure: tanpa identitas produk terverifikasi hasil FEP/SCEP dapat salah atribusi.",
	Query:  forefrontServiceQuery, ParseDate: parseForefrontDate, ExampleHours: 72, TemplateID: "av-not-updated-forefront", Collect: collectForefront,
}

// FILETIME is unsigned 100 ns ticks since 1601-01-01 UTC. The parser
// accepts exactly the canonical comma-separated decimal bytes of RegistryBinary.
func parseForefrontDate(raw string) (time.Time, bool) {
	parts := strings.Split(raw, ",")
	if len(parts) != 8 {
		return time.Time{}, false
	}
	var b [8]byte
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil || strconv.FormatUint(n, 10) != p {
			return time.Time{}, false
		}
		b[i] = byte(n)
	}
	ticks := binary.LittleEndian.Uint64(b[:])
	const epoch = uint64(116444736000000000)
	if ticks < epoch || ticks > epoch+uint64(1<<63)/100 {
		return time.Time{}, false
	}
	delta := ticks - epoch
	return time.Unix(int64(delta/10000000), int64(delta%10000000)*100).UTC(), true
}
func forefrontBinary(r RegistryResult, checked time.Time) time.Time {
	if r.Status != RegistryFound || len(r.Values) != 8 {
		return time.Time{}
	}
	ts, ok := parseForefrontDate(strings.Join(r.Values, ","))
	if !ok || ts.After(checked) {
		return time.Time{}
	}
	return ts
}
func collectForefront(ctx context.Context, s Session, checked time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, forefrontServiceQuery)
	if e := ctx.Err(); e != nil {
		return Observation{}, e
	}
	if err != nil {
		return out, err
	}
	var fcs, ms *map[string]string
	for i := range rows {
		switch {
		case strings.EqualFold(rows[i]["name"], "FCSAM"):
			fcs = &rows[i]
		case strings.EqualFold(rows[i]["name"], "MsMpSvc"):
			ms = &rows[i]
		}
	}
	if fcs == nil && ms == nil {
		return out, nil
	}
	key := forefrontFCS
	value := "AVSignatureApplied"
	service := fcs
	if fcs == nil {
		key = forefrontMAR
		value = "SignaturesLastUpdated"
		service = ms
	}
	r := s.RegistryBinary(ctx, key, value)
	if e := ctx.Err(); e != nil {
		return Observation{}, e
	}
	// A missing value alone is not proof of installation. For FEP/SCEP the
	// fallback is documented by T1/T2, but only after the specific key is found.
	if fcs == nil && r.Status == RegistryNotFound {
		r = s.RegistryBinary(ctx, key, "AVSignatureApplied")
		if e := ctx.Err(); e != nil {
			return Observation{}, e
		}
	}
	if r.Status == RegistryNotFound || r.Status == RegistryDenied || r.Status == RegistryError {
		return out, nil
	}
	out.SignatureLastUpdated = forefrontBinary(r, checked)
	switch {
	case strings.EqualFold((*service)["state"], "Stopped") || strings.EqualFold((*service)["startmode"], "Disabled"):
		out.Active = "disabled"
	case strings.EqualFold((*service)["state"], "Running"):
		out.Active = "enabled"
	}
	if fcs == nil {
		eol := s.RegistryDWORD(ctx, forefrontMARoot, "EndOfLifeState")
		if e := ctx.Err(); e != nil {
			return Observation{}, e
		}
		if eol.Status == RegistryFound && len(eol.Values) == 1 && eol.Values[0] == "3" {
			out.Active = "disabled"
		}
		if eol.Status == RegistryDenied || eol.Status == RegistryError {
			out.Active = "unknown"
		}
	}
	return out, nil
}
