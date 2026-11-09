package collector

import (
	"eguard-nac-agent/core"
	"strings"
)

type AVProduct struct {
	Name  string `json:"name"`
	State uint32 `json:"state"`
}
type DefenderStatus struct {
	Present       bool `json:"present"`
	AMRunning     bool `json:"am_running"`
	Realtime      bool `json:"realtime"`
	SignaturesAge int  `json:"signatures_age_days"`
}

func normalizeDomain(joined bool, domain, expected string) core.DomainEvidence {
	d := core.DomainEvidence{PartOfDomain: core.No, Match: core.Unknown}
	if !joined {
		return d
	}
	d.PartOfDomain = core.Yes
	if domain == "" || expected == "" {
		return d
	}
	if strings.EqualFold(domain, expected) {
		d.Match = core.Yes
	} else {
		d.Match = core.No
	}
	return d
}

// defenderSecurityCenterNames are the exact SecurityCenter2 display names Windows
// registers for Microsoft Defender itself. Exact match only: lookalike vendor names
// stay opaque third-party products.
var defenderSecurityCenterNames = map[string]bool{"windows defender": true, "microsoft defender antivirus": true}

func normalizeAV(products []AVProduct, defender DefenderStatus) core.AVEvidence {
	a := core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown}
	if len(products) > 0 || defender.Present {
		a.Installed = core.Yes
	}
	// SecurityCenter2 productState encoding is vendor-dependent. Never infer running or updated from it.
	// Defender's own SC2 entry is the same product as the Defender WMI evidence; only
	// other vendors are opaque.
	others := 0
	for _, product := range products {
		if !(defender.Present && defenderSecurityCenterNames[strings.ToLower(strings.TrimSpace(product.Name))]) {
			others++
		}
	}
	if defender.Present {
		if defender.AMRunning && defender.Realtime {
			// Defender health cannot establish health of a second, opaque vendor product.
			if others == 0 {
				a.Running = core.Yes
			}
		} else if others == 0 {
			a.Running = core.No
		}
		if others == 0 && a.Running == core.Yes {
			if defender.SignaturesAge >= 0 && defender.SignaturesAge <= 3 {
				a.Updated = core.Yes
			}
			if defender.SignaturesAge > 3 {
				a.Updated = core.No
			}
		}
	}
	return a
}
func normalizeFirewall(profiles map[string]bool) map[string]core.Evidence {
	result := map[string]core.Evidence{}
	for _, name := range []string{"domain", "private", "public"} {
		e := core.Evidence{Value: core.Unknown, Source: "INetFwPolicy2", Error: "profile query unavailable"}
		if enabled, ok := profiles[name]; ok {
			e.Error = ""
			if enabled {
				e.Value = core.Yes
			} else {
				e.Value = core.No
			}
		}
		result[name] = e
	}
	return result
}
func adapterKind(name string, hardware *bool) string {
	if hardware == nil {
		return Classify(name)
	}
	if Classify(name) == "virtual" {
		if *hardware {
			return "unknown"
		}
		return "virtual"
	}
	if *hardware {
		return "physical"
	}
	return "virtual"
}
