package collector

import (
	"eguard-nac-agent/core"
	"sort"
	"strings"
	"unicode"
)

// cleanText trims, drops control characters and bounds length.
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > core.MaxInventoryText {
		s = s[:core.MaxInventoryText]
	}
	return strings.TrimSpace(s)
}

// NormalizeSoftware de-duplicates (name+version), drops unnamed entries,
// sorts by name and bounds the list. truncated reports the bound was hit.
func NormalizeSoftware(in []core.SoftwareItem) (out []core.SoftwareItem, truncated bool) {
	seen := map[string]bool{}
	for _, it := range in {
		it = core.SoftwareItem{Name: cleanText(it.Name), Version: cleanText(it.Version), Publisher: cleanText(it.Publisher)}
		if it.Name == "" {
			continue
		}
		k := strings.ToLower(it.Name) + "\x00" + strings.ToLower(it.Version)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].Version < out[j].Version
	})
	if len(out) > core.MaxSoftwareItems {
		return out[:core.MaxSoftwareItems], true
	}
	if out == nil {
		out = []core.SoftwareItem{}
	}
	return out, false
}

// CleanUser keeps DOMAIN\user or user; empty when none is signed in.
func CleanUser(s string) string {
	s = cleanText(s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
