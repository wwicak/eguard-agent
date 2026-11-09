//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// enableOwnerPrivileges enables SeRestorePrivilege and SeTakeOwnershipPrivilege
// on the elevated installer's own token. Administrators hold both; Windows only
// lets a process assign BUILTIN\Administrators or SYSTEM as owner of the
// protected NAC files when they are enabled (otherwise some UAC/domain admin
// tokens fail with ERROR_INVALID_OWNER, "This security ID may not be assigned
// as the owner of this object"). Nothing else is granted.
func enableOwnerPrivileges() {
	var tok windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok) != nil {
		return
	}
	defer tok.Close()
	for _, name := range []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"} {
		var luid windows.LUID
		if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(tok, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
	}
}
