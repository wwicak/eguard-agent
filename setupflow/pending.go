package setupflow

import "strings"

// RemovePendingNAC removes complete source/destination pairs touching only the
// dedicated installation directory. PendingFileRenameOperations is REG_MULTI_SZ
// of pairs; never treat an unmatched final entry as a pair.
func RemovePendingNAC(entries []string) []string {
	out := make([]string, 0, len(entries))
	for i := 0; i < len(entries); i += 2 {
		if i+1 == len(entries) {
			out = append(out, entries[i])
			break
		}
		if nacPath(entries[i]) || nacPath(entries[i+1]) {
			continue
		}
		out = append(out, entries[i], entries[i+1])
	}
	return out
}
func nacPath(p string) bool {
	p = strings.TrimPrefix(p, "!")
	// Windows 10/11 prefix delete-on-reboot entries with "*<n>" (observed:
	// `*1\??\C:\Program Files\eGuard NAC\eguard-nac-service.exe`).
	if strings.HasPrefix(p, "*") {
		i := 1
		for i < len(p) && p[i] >= '0' && p[i] <= '9' {
			i++
		}
		p = p[i:]
	}
	p = strings.TrimPrefix(p, `\??\`)
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.ToLower(p)
	dir := strings.ToLower(`C:\Program Files\eGuard NAC`)
	return p == dir || strings.HasPrefix(p, dir+`\`)
}
