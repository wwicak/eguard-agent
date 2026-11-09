//go:build windows

package installtransaction

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Real SCM integration test. Runs only on an approved Windows tester VM with
// EGUARD_NAC_SCM_ITEST=1 and the fixed service binary already placed at
// BinaryPath. The production service has a nil runner factory, so it must never
// become operational; the transaction must therefore fail and roll back the
// service it created, leaving no eGuardNAC service behind.
func TestRealSCMTransactionRollsBackFailClosedService(t *testing.T) {
	if os.Getenv("EGUARD_NAC_SCM_ITEST") != "1" {
		t.Skip("real SCM test requires EGUARD_NAC_SCM_ITEST=1 on an approved tester VM")
	}
	if _, err := os.Stat(BinaryPath); err != nil {
		t.Fatalf("service binary missing at fixed path: %v", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect SCM: %v", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		t.Fatal("precondition: eGuardNAC service already exists; refusing to touch it")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	err = Run(ctx, NewSCM(), 250*time.Millisecond)
	t.Logf("transaction duration: %s", time.Since(started).Round(time.Millisecond))
	if err == nil {
		t.Fatal("transaction succeeded although production readiness is not wired")
	}
	t.Logf("transaction error (expected fail-closed): %v", err)
	if !errors.Is(err, ErrServiceExited) {
		t.Fatalf("fail-closed nil-factory service must be detected as exited, got: %v", err)
	}
	if errors.Is(err, ErrExisting) {
		t.Fatalf("owned service misidentified as foreign (ImagePath comparison bug): %v", err)
	}

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		t.Fatal("rollback left eGuardNAC service installed")
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		t.Fatalf("unexpected post-rollback lookup error: %v", err)
	}
}
