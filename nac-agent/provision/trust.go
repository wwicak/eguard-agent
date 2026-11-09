package provision

import (
	"bytes"
	"eguard-nac-agent/bootstrap"
)

// CheckEnrollmentTrust prevents a signed response from silently replacing the
// operator-pinned enrollment CA or origin in neutral builds.
func CheckEnrollmentTrust(root string, v bootstrap.Verified) error {
	if BootstrapPinHex != "" {
		return nil
	}
	r, e := LoadIdentity(root)
	if e != nil {
		return e
	}
	der, _, e := r.Identity.Material()
	if e != nil {
		return e
	}
	if v.Origin() != "https://"+r.Server || !bytes.Equal(v.ServerCADER(), der) {
		return ErrInvalid
	}
	return nil
}
