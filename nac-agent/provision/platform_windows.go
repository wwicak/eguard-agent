//go:build windows

package provision

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

// checkPath: every existing component must not be a reparse point; the final
// component (an owned provisioning object) must also satisfy the owner/DACL policy.
func checkPath(p string) error { return walk(p, true) }

// checkAncestors applies only the reparse-point rule. Ancestors such as
// C:\ProgramData legitimately allow Users to create subdirectories, so the strict
// owned-object ACL policy must not be applied to them.
func checkAncestors(p string) error { return walk(p, false) }

func walk(p string, final bool) error {
	abs, e := filepath.Abs(p)
	if e != nil {
		return e
	}
	vol := filepath.VolumeName(abs)
	if vol == "" {
		return ErrInvalid
	}
	parts := strings.Split(strings.TrimPrefix(abs[len(vol):], `\`), `\`)
	cur := vol + `\`
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		i, e := os.Lstat(cur)
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 || i.Mode()&os.ModeIrregular != 0 {
			return ErrInvalid
		}
		attrs, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(cur))
		if e != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrInvalid
		}
		if !final || cur != abs {
			continue
		} // Ancestors are checked for reparse; ACL policy applies to owned provisioning objects.
		sd, e := windows.GetNamedSecurityInfo(cur, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			return e
		}
		owner, _, e := sd.Owner()
		if e != nil || owner == nil || !privileged(owner) {
			return ErrInvalid
		}
		acl, _, e := sd.DACL()
		if e != nil || acl == nil {
			return ErrInvalid
		}
		for j := uint32(0); j < uint32(acl.AceCount); j++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if e = windows.GetAce(acl, j, &ace); e != nil || ace == nil {
				return ErrInvalid
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
				return ErrInvalid
			}
			if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
				sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
				if !privileged(sid) && ace.Mask&dangerous != 0 {
					return ErrInvalid
				}
			}
		}
	}
	return nil
}
func privileged(s *windows.SID) bool {
	return s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

const dangerous = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL | 0x40 // FILE_DELETE_CHILD
const aclSDDL = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)"

func secure(p string) error {
	sd, e := windows.SecurityDescriptorFromString(aclSDDL)
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, adminSID(), nil, acl, nil)
}
func adminSID() *windows.SID {
	s, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	return s
}
func prepareRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return ErrInvalid
	}
	parent := filepath.Dir(root)
	if e := checkAncestors(parent); e != nil {
		return e
	}
	if _, e := os.Lstat(root); os.IsNotExist(e) {
		// Create with the protected DACL atomically: no window in which the
		// directory carries ProgramData's inherited Users-writable ACL.
		sd, e := windows.SecurityDescriptorFromString(aclSDDL)
		if e != nil {
			return e
		}
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		name, e := windows.UTF16PtrFromString(root)
		if e != nil {
			return e
		}
		if e = windows.CreateDirectory(name, &sa); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	// An existing root is never re-ACLed/adopted: it must already be compliant.
	return checkPath(root)
}
func protectFile(p string) error { return secure(p) }
