package installtransaction

import "strings"

// expectedImagePath is the ImagePath the Windows SCM stores for BinaryPath when
// created through mgr.CreateService (which applies syscall.EscapeArg). The fixed
// BinaryPath contains spaces but no quotes or trailing backslash, so EscapeArg
// yields exactly the path wrapped in double quotes. Kept platform-neutral so the
// rule is unit-tested on Linux; the Windows adapter compares against it.
func expectedImagePath() string {
	if strings.ContainsAny(BinaryPath, " \t") {
		return `"` + BinaryPath + `"`
	}
	return BinaryPath
}
