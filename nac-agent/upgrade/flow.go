package upgrade

import "errors"

// Steps is restricted to replacement of the fixed service binary. Provisioning,
// enrollment, credentials and journal are deliberately absent from this interface.
type Steps interface {
	Preflight() error
	Relax() error
	Protect() error
	Stop() error
	Backup() error
	Replace() error
	StartReady() error
	Restore() error
}

func Run(s Steps) (err error) {
	if err = s.Preflight(); err != nil {
		return err
	}
	// Even partial relaxation failure must attempt to restore the signed selection.
	defer func() { err = errors.Join(err, s.Protect()) }()
	if err = s.Relax(); err != nil {
		return err
	}
	if err = s.Stop(); err != nil {
		return err
	}
	if err = s.Backup(); err != nil {
		return errors.Join(err, s.StartReady())
	}
	rollback := func(cause error) error {
		if e := s.Stop(); e != nil {
			return errors.Join(cause, e)
		}
		if e := s.Restore(); e != nil {
			return errors.Join(cause, e)
		}
		return errors.Join(cause, s.StartReady())
	}
	if err = s.Replace(); err != nil {
		return rollback(err)
	}
	if err = s.StartReady(); err != nil {
		return rollback(err)
	}
	return nil
}
