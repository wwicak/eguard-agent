//go:build linux || darwin

package unixagent

import "eguard-nac-agent/selfenroll"

func selfValidate(server, fp, code string) error {
	if e := selfenroll.ValidateServer(server); e != nil {
		return e
	}
	if e := selfenroll.ValidateFingerprint(fp); e != nil {
		return e
	}
	_, e := selfenroll.Normalize(code)
	return e
}
