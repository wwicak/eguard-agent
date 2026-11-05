// Package cleanup performs the official NAC-only removal after a signed terminal
// lifecycle state (Temporary expiry or accepted uninstall authorization). It never
// touches EDR, OS logs or other applications: every step is scoped to fixed NAC
// resources and the exact machine-certificate fingerprint from the signed bootstrap.
package cleanup

import "errors"

type Adapter interface {
	// MarkServiceForDeletion deletes the eGuardNAC service registration. When called
	// from the running service, SCM removes it once the process exits.
	MarkServiceForDeletion() error
	// RemoveMachineCredential deletes exactly the certificate (and its CNG key) whose
	// leaf DER SHA-256 equals fp from LocalMachine\MY.
	RemoveMachineCredential(fp [32]byte) error
	// RemoveProvisioning deletes the fixed provisioning root (bootstrap, state, journal).
	RemoveProvisioning() error
	// ScheduleBinaryRemoval removes or schedules (delete-on-reboot) the fixed
	// installation directory, which is in use by the running service.
	ScheduleBinaryRemoval() error
}

var ErrAdapter = errors.New("cleanup adapter missing")

// Run is best-effort and idempotent: all steps are attempted and every failure is
// returned joined, so a partially failed cleanup is visible and can be retried on
// the next boot.
func Run(a Adapter, machineCert [32]byte) error {
	if a == nil {
		return ErrAdapter
	}
	return errors.Join(
		a.MarkServiceForDeletion(),
		a.RemoveMachineCredential(machineCert),
		a.RemoveProvisioning(),
		a.ScheduleBinaryRemoval(),
	)
}
