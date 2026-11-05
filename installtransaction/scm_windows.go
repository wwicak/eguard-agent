//go:build windows

package installtransaction

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// SCM operates exclusively on the fixed NAC service; it does not access files.
// Only the successful CreateService handle establishes transaction ownership.
type SCM struct{ owned bool }

func NewSCM() *SCM { return &SCM{} }

func open() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(ServiceName)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}
func check(s *mgr.Service) error {
	c, err := s.Config()
	if err != nil {
		return err
	}
	if c.BinaryPathName != expectedImagePath() || c.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || c.StartType != mgr.StartAutomatic || c.ServiceStartName != "LocalSystem" || len(c.Dependencies) != 0 {
		return ErrExisting
	}
	return nil
}
func (a *SCM) Lookup(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	m, s, err := open()
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return Snapshot{State: Missing}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	defer m.Disconnect()
	defer s.Close()
	if err = check(s); err != nil {
		return Snapshot{}, err
	}
	status, err := s.Query()
	if err != nil {
		return Snapshot{}, err
	}
	state := Pending
	switch status.State {
	case svc.Running:
		state = Running
	case svc.Stopped:
		state = Stopped
	}
	return Snapshot{State: state, Binary: BinaryPath}, nil
}
func (a *SCM) Create(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	s, err := m.CreateService(ServiceName, BinaryPath, mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, ServiceStartName: "LocalSystem", DisplayName: "eGuard NAC"})
	if err != nil {
		return false, err
	}
	a.owned = true
	defer s.Close()
	if err = check(s); err != nil {
		return true, err
	}
	return true, nil
}
func (a *SCM) ownedService(ctx context.Context) (*mgr.Mgr, *mgr.Service, error) {
	if !a.owned {
		return nil, nil, ErrExisting
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	m, s, err := open()
	if err != nil {
		return nil, nil, err
	}
	if err = check(s); err != nil {
		s.Close()
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}
func (a *SCM) Start(ctx context.Context) error {
	m, s, err := a.ownedService(ctx)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	return s.Start()
}
func (a *SCM) Stop(ctx context.Context) error {
	m, s, err := a.ownedService(ctx)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped || status.State == svc.StopPending {
		return nil
	}
	_, err = s.Control(svc.Stop)
	return err
}
func (a *SCM) Delete(ctx context.Context) error {
	m, s, err := a.ownedService(ctx)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		return fmt.Errorf("service not stopped: %v", status.State)
	}
	return s.Delete()
}

// Ready requires the owned service to stay Running for StabilityWindow. Because
// servicehost reports Running only after the verified production factory
// succeeded, this is operational evidence, not merely "process started".
func (a *SCM) Ready(ctx context.Context) error {
	if !a.owned {
		return ErrExisting
	}
	return stableRunning(ctx, a.Lookup, StabilityWindow, 500*time.Millisecond)
}
