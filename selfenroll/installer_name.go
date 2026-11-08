package selfenroll

import "strings"

// CodeFromInstallerName extracts a display-form code from a bare installer
// filename (not a path). Only XXXXX-XXXXX, optionally followed by a browser's
// " (digits)" or "(digits)" duplicate suffix, then .exe, is accepted.
// Keep these rules in sync with CodeFromInstallerName in the NSIS installer.
func CodeFromInstallerName(name string) (string, bool) {
	if len(name) > 255 || strings.ContainsAny(name, "/\\:*?\"<>|\r\n\t") || len(name) < 4 || !strings.EqualFold(name[len(name)-4:], ".exe") {
		return "", false
	}
	stem := name[:len(name)-4]
	if strings.HasSuffix(stem, ")") {
		i := len(stem) - 2
		end := i
		for i >= 0 && stem[i] >= '0' && stem[i] <= '9' {
			i--
		}
		if i == end || i < 0 || stem[i] != '(' {
			return "", false
		}
		stem = strings.TrimSuffix(stem[:i], " ")
	}
	i := strings.LastIndexByte(stem, '_')
	if i < 0 {
		return "", false
	}
	code := stem[i+1:]
	if len(code) != 11 || code[5] != '-' {
		return "", false
	}
	normalized, err := Normalize(code)
	if err != nil {
		return "", false
	}
	return normalized[:5] + "-" + normalized[5:], true
}
