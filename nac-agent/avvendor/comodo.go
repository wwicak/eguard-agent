package avvendor

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Fixed root/cimv2 and HKLM-only reads. No database file mtime is used as an update date.
const comodoServiceQuery = "SELECT Name,State,StartMode,PathName FROM Win32_Service WHERE Name='CmdAgent'"
const (
	comodoConfigBase = `SYSTEM\CurrentControlSet\Services\CmdAgent\CisConfigs`
	comodoLegacyBase = `SYSTEM\Software\COMODO\Firewall Pro\Configurations`
)

var comodo = Descriptor{
	ID: "comodo", DisplayName: "Comodo Internet Security / Xcitium Client Security (unverified)",
	Source: "Win32_Service CmdAgent (root/cimv2); HKLM SYSTEM\\CurrentControlSet\\Services\\CmdAgent\\CisConfigs Active / <n>\\AV\\Settings\\RealTime ScanningMode, fallback HKLM SYSTEM\\Software\\COMODO\\Firewall Pro\\Configurations <n>\\AV\\Settings\\RealTime ScanningMode dan InstallPath (forum Comodo dan Forescout: pihak ketiga); belum diverifikasi lab (disetujui Boss)",
	Query:  comodoServiceQuery, StatusOnly: true, TemplateID: "av-not-active-comodo", Collect: collectComodo,
}

// RegistryDWORD returns a decimal string. Never interpolate provider-supplied
// config numbers into a path: only the documented CisConfigs slot 0 is a
// fallback, and other slots require a bounded numeric Active value.
func comodoSlot(r RegistryResult) (string, bool) {
	if r.Status != RegistryFound || len(r.Values) != 1 {
		return "", false
	}
	n, err := strconv.ParseUint(r.Values[0], 10, 32)
	if err != nil || n > 255 {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}

func collectComodo(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, comodoServiceQuery)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err != nil {
		return out, nil
	}
	if len(rows) == 0 {
		// Legacy InstallPath can establish presence but not RTP status.
		_ = s.RegistryString(ctx, comodoLegacyBase, "InstallPath")
		if err := ctx.Err(); err != nil {
			return out, err
		}
		return out, nil
	}
	if len(rows) != 1 || !strings.EqualFold(rows[0]["name"], "CmdAgent") {
		return out, nil
	}
	if !strings.EqualFold(rows[0]["state"], "Running") {
		if rows[0]["state"] != "" {
			out.Active = "disabled"
		}
		return out, nil
	}
	cfg := s.RegistryDWORD(ctx, comodoConfigBase, "Active")
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	slot := "0" // documented fallback when Active is absent
	if cfg.Status == RegistryFound {
		var ok bool
		slot, ok = comodoSlot(cfg)
		if !ok {
			return out, nil
		}
	} else if cfg.Status != RegistryNotFound {
		return out, nil
	}
	suffix := `\` + slot + `\AV\Settings\RealTime`
	mode := s.RegistryDWORD(ctx, comodoConfigBase+suffix, "ScanningMode")
	if err := ctx.Err(); err != nil {
		return Observation{Active: "unknown"}, err
	}
	if mode.Status == RegistryNotFound {
		mode = s.RegistryDWORD(ctx, comodoLegacyBase+suffix, "ScanningMode")
		if err := ctx.Err(); err != nil {
			return Observation{Active: "unknown"}, err
		}
	}
	value, ok := comodoSlot(mode)
	if !ok {
		return out, nil
	}
	switch value {
	case "0":
		out.Active = "disabled"
	case "3":
		out.Active = "enabled"
		// Other modes have no proven meaning, so do not assert protection.
	}
	return out, nil
}
