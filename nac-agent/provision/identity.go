package provision

import (
	"crypto/ed25519"
	"eguard-nac-agent/selfenroll"
	"encoding/json"
	"errors"
	"runtime"
)

const IdentityFile = "enrollment-identity.json"

type EnrollmentIdentity struct {
	Server      string              `json:"server"`
	Identity    selfenroll.Identity `json:"identity"`
	Fingerprint string              `json:"fingerprint"`
}

func (r EnrollmentIdentity) Validate() error {
	if e := selfenroll.ValidateServer(r.Server); e != nil {
		return e
	}
	if e := selfenroll.ValidateFingerprint(r.Fingerprint); e != nil {
		return e
	}
	fp, e := r.Identity.Fingerprint()
	if e != nil {
		return e
	}
	if fp != r.Fingerprint {
		return errors.New("persisted enrollment identity fingerprint mismatch")
	}
	return nil
}

func WriteIdentity(root, server string, id selfenroll.Identity, fp string) error {
	return writeIdentityRecord(root, EnrollmentIdentity{Server: server, Identity: id, Fingerprint: fp})
}
func writeIdentityRecord(root string, r EnrollmentIdentity) error {
	if e := r.Validate(); e != nil {
		return e
	}
	if e := prepareRoot(root); e != nil {
		return e
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return atomic(root, IdentityFile, raw)
}
func LoadIdentity(root string) (EnrollmentIdentity, error) {
	var r EnrollmentIdentity
	if e := safe(root); e != nil {
		return r, e
	}
	raw, e := read(root, IdentityFile, 96<<10)
	if e != nil {
		return r, e
	}
	if exact(raw, "server", "identity", "fingerprint") != nil {
		return r, ErrInvalid
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || exact(m["identity"], "version", "ca_der_b64", "bootstrap_pin") != nil {
		return r, ErrInvalid
	}
	if json.Unmarshal(raw, &r) != nil {
		return r, ErrInvalid
	}
	return r, r.Validate()
}

// PinForRoot preserves stamped Windows trust; neutral builds authenticate the
// persisted key against the CA+operator fingerprint on every load/start.
func PinForRoot(root string) (ed25519.PublicKey, error) {
	if BootstrapPinHex != "" || runtime.GOOS == "windows" {
		return Pin()
	}
	r, e := LoadIdentity(root)
	if e != nil {
		return nil, e
	}
	_, pin, e := r.Identity.Material()
	return ed25519.PublicKey(pin), e
}
