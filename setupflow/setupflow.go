// Package setupflow orders the installer steps and undoes only what the current
// run completed when a later step fails. Platform work lives in the Steps adapter.
package setupflow

import "errors"

type Steps interface {
	// Preflight refuses (without side effects) when not elevated, when any NAC
	// resource already exists (no silent adoption/upgrade), or inputs are missing.
	Preflight() error
	Enroll() error           // admission.Install: verify signed material, write store+journal
	PlaceBinary() error      // copy service binary to the fixed install dir
	RegisterEventLog() error // Application event source for the service
	InstallService() error   // installtransaction.Run (self-rolling-back, readiness-gated)
	ProtectService() error   // apply signed Anti-Tamper selection to the running service

	RemoveService() error // stop + delete the service this run created

	RemoveProvisioning() error
	RemoveBinary() error
	RemoveEventLog() error
}

var ErrSteps = errors.New("installer steps missing")

func Install(s Steps) error {
	if s == nil {
		return ErrSteps
	}
	if e := s.Preflight(); e != nil {
		return e
	}
	var undo []func() error
	fail := func(e error) error {
		errs := []error{e}
		for i := len(undo) - 1; i >= 0; i-- {
			errs = append(errs, undo[i]())
		}
		return errors.Join(errs...)
	}
	if e := s.Enroll(); e != nil {
		return fail(e)
	}
	undo = append(undo, s.RemoveProvisioning)
	if e := s.PlaceBinary(); e != nil {
		return fail(e)
	}
	undo = append(undo, s.RemoveBinary)
	if e := s.RegisterEventLog(); e != nil {
		return fail(e)
	}
	undo = append(undo, s.RemoveEventLog)
	if e := s.InstallService(); e != nil {
		return fail(e)
	}
	undo = append(undo, s.RemoveService)
	if e := s.ProtectService(); e != nil {
		return fail(e)
	}
	return nil
}
