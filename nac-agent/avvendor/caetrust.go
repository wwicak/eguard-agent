package avvendor

import (
	"context"
	"strings"
	"time"
)

// Fixed root/cimv2 service metadata and HKLM-only installation markers.
const caetrustServiceQuery = "SELECT Name,State,StartMode FROM Win32_Service WHERE Name='InoRT' OR Name='InoTask' OR Name='InoRPC'"
const (
	caetrustNative = `SOFTWARE\ComputerAssociates`
	caetrustWow    = `SOFTWARE\Wow6432Node\ComputerAssociates`
)

var caetrust = Descriptor{
	ID: "caetrust", DisplayName: "CA eTrust / CA Anti-Virus (EOL) (unverified)",
	Source: "WinRM root/cimv2 Win32_Service InoRT/InoTask/InoRPC (pihak ketiga: https://bleepingcomputer.com/forums/t/57773/infected-with-trust-cleaner); HKLM SOFTWARE\\ComputerAssociates dan SOFTWARE\\Wow6432Node\\ComputerAssociates (resmi: https://learn.microsoft.com/en-us/previous-versions/office/exchange-server-analyzer/aa998314(v=exchg.80); Wow6432Node belum terbukti). eTrust r7.1 End of Service 31 Desember 2008 (resmi: https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/release-announcements/CA-Anti-Virus-for-the-Enterprise-for-Windows-Compatibility-Matrix/2986); r8/ITM EOL disimpulkan dari peralihan ke Total Defense r12 (resmi: https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/release-announcements/Internet-Security-Product-Support-is-Shifting-to-Total-Defense-Click-here-for-Details/8587); belum diverifikasi lab (disetujui Boss)",
	Query:  caetrustServiceQuery, StatusOnly: true, TemplateID: "av-not-active-caetrust", ExampleHours: 0,
	Collect: collectCAeTrust,
}

func collectCAeTrust(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rows, err := s.Enumerate(ctx, caetrustServiceQuery)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, nil
	} // Denied/transport failure is not absence.
	if len(rows) == 0 {
		out.Absent = true
		return out, nil
	}
	for _, row := range rows {
		if !strings.EqualFold(row["name"], "InoRT") {
			continue
		}
		if strings.EqualFold(row["startmode"], "Disabled") || (row["state"] != "" && !strings.EqualFold(row["state"], "Running")) {
			out.Active = "disabled"
		} else if strings.EqualFold(row["state"], "Running") {
			out.Active = "enabled"
		}
		return out, nil
	}
	// Installation markers distinguish an absent realtime service from an
	// uninstalled product; neither is evidence that realtime protection is on.
	for _, key := range []string{caetrustNative, caetrustWow} {
		if err := ctx.Err(); err != nil {
			return Observation{Active: "unknown"}, err
		}
		result := s.RegistrySubkeys(ctx, key)
		if err := ctx.Err(); err != nil {
			return Observation{Active: "unknown"}, err
		}
		if result.Status == RegistryFound {
			for _, subkey := range result.Values {
				switch {
				case strings.EqualFold(subkey, "eTrustAntivirus"), strings.EqualFold(subkey, "eTrustITM"), strings.EqualFold(subkey, "InoculateIT"), strings.EqualFold(subkey, "ScanEngine"):
					return out, nil
				}
			}
		}
	}
	return out, nil
}
