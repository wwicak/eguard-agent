package avvendor

import (
	"context"
	"strings"
	"time"
)

// MSE and FEP/SCEP share MsMpSvc. Never attribute the service without an
// unambiguous MSE uninstall DisplayName. All paths are fixed HKLM reads.
const mseServiceQuery = "SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service WHERE Name='MsMpSvc'"
const mseUninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
const mseRTPKey = `SOFTWARE\Microsoft\Microsoft Antimalware\Real-Time Protection`

var mse = Descriptor{
	ID: "mse", DisplayName: "Microsoft Security Essentials (EOL 2020) (unverified)",
	Source: "EOL 14 Januari 2020 (resmi: https://support.microsoft.com/en-us/security/what-is-microsoft-security-essentials); HKLM Uninstall DisplayName Microsoft Security Essentials (pihak ketiga: https://stackoverflow.com/questions/19190388/checking-if-microsoft-security-essentials-is-installed-on-machine); MsMpSvc Win32_Service (resmi SCEP: https://learn.microsoft.com/en-us/archive/blogs/technet/mspfe/what-to-do-when-system-center-2012-endpoint-protection-rc-installation-fails; pihak ketiga MSE: https://superuser.com/questions/573826/disable-msmpsvc-from-command-line); HKLM Microsoft Antimalware Real-Time Protection DisableRealtimeMonitoring (pihak ketiga: http://grouppolicy.biz/2010/12/group-policy-for-microsoft-security-essentials-2-0); belum diverifikasi lab (disetujui Boss)",
	Query:  mseServiceQuery, StatusOnly: true, ExampleHours: 0, TemplateID: "av-not-active-mse", Collect: collectMSE,
}

func collectMSE(ctx context.Context, s Session, _ time.Time) (Observation, error) {
	out := Observation{Active: "unknown"}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	keys := s.RegistrySubkeys(ctx, mseUninstallKey)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if keys.Status != RegistryFound || len(keys.Values) == 0 {
		return out, nil
	}
	// An unreadable or competing product marker makes attribution unsafe.
	mseFound := false
	for _, sub := range keys.Values {
		if sub == "" || strings.ContainsAny(sub, `\/`) {
			return out, nil
		}
		r := s.RegistryString(ctx, mseUninstallKey+`\`+sub, "DisplayName")
		if err := ctx.Err(); err != nil {
			return out, err
		}
		switch r.Status {
		case RegistryNotFound:
			continue
		case RegistryFound:
			if len(r.Values) != 1 {
				return out, nil
			}
			switch {
			case strings.EqualFold(r.Values[0], "Microsoft Security Essentials"):
				mseFound = true
			case strings.EqualFold(r.Values[0], "System Center Endpoint Protection"), strings.EqualFold(r.Values[0], "Forefront Endpoint Protection"):
				return out, nil
			}
		default:
			return out, nil
		}
	}
	if !mseFound {
		return out, nil
	}
	rows, err := s.Enumerate(ctx, mseServiceQuery)
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if err != nil || len(rows) != 1 || !strings.EqualFold(rows[0]["name"], "MsMpSvc") {
		return out, nil
	}
	r := s.RegistryDWORD(ctx, mseRTPKey, "DisableRealtimeMonitoring")
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if r.Status != RegistryNotFound && (r.Status != RegistryFound || len(r.Values) != 1 || (r.Values[0] != "0" && r.Values[0] != "1")) {
		return out, nil
	}
	if r.Status == RegistryFound && r.Values[0] == "1" || strings.EqualFold(rows[0]["startmode"], "Disabled") || strings.EqualFold(rows[0]["state"], "Stopped") {
		out.Active = "disabled"
	} else if strings.EqualFold(rows[0]["state"], "Running") {
		out.Active = "enabled"
	}
	return out, nil
}
