package servicefactory

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"eguard-nac-agent/clockguard"
	"eguard-nac-agent/servicehost"
)

// Clock rolled back across a reboot (before the signed expiry) must not reopen an
// expired Temporary session: the durable high-water mark is used for expiry.
func TestClockRollbackAfterExpiryStillCleansUp(t *testing.T) {
	r := setup(t, false)
	real := time.Now().Unix()
	r.accept(t, "activate", "temporary", 1, real-200, fmt.Sprint(real-20), real-150)
	// Last trusted sample (persisted before "reboot") was after expiry.
	if e := clockguard.Raise(filepath.Join(r.root, ClockFile), time.Unix(real, 0)); e != nil {
		t.Fatal(e)
	}
	d := r.deps()
	rolled := time.Unix(real-100, 0) // attacker sets clock back before expiry
	d.Now = func() (time.Time, error) { return rolled, nil }
	var got string
	d.OnTerminal = func(s string, _ [32]byte) error { got = s; return nil }
	_ = servicehost.Run(New(d), make(chan servicehost.Command), nil)
	if got != StateExpired {
		t.Fatalf("rollback reopened session: terminal=%q", got)
	}
	if r.collected.Load() != 0 || r.received.Load() != 0 {
		t.Fatal("collected/sent after rollback past expiry")
	}
}

// A Permanent device whose clock is rolled back far beyond tolerance must not
// report fresh posture (fail closed), but is not uninstalled.
func TestPermanentLargeRollbackFailsClosedNoCleanup(t *testing.T) {
	r := setup(t, false)
	real := time.Now().Unix()
	r.accept(t, "activate", "permanent", 1, real-200, "null", real-150)
	if e := clockguard.Raise(filepath.Join(r.root, ClockFile), time.Unix(real, 0)); e != nil {
		t.Fatal(e)
	}
	d := r.deps()
	d.Now = func() (time.Time, error) { return time.Unix(real-3600, 0), nil }
	called := false
	d.OnTerminal = func(string, [32]byte) error { called = true; return nil }
	e := servicehost.Run(New(d), make(chan servicehost.Command), nil)
	if e == nil || called || r.received.Load() != 0 {
		t.Fatalf("e=%v cleanup=%v received=%d", e, called, r.received.Load())
	}
}

// Normal operation raises the durable mark.
func TestRunRaisesHighWater(t *testing.T) {
	r := setup(t, false)
	now := time.Now().Unix()
	r.accept(t, "activate", "permanent", 1, now-100, "null", now-50)
	commands := make(chan servicehost.Command, 1)
	done := make(chan error, 1)
	go func() { done <- servicehost.Run(New(r.deps()), commands, nil) }()
	waitDelivery(t, r)
	commands <- servicehost.Stop
	<-done
	hw, e := clockguard.Load(filepath.Join(r.root, ClockFile))
	if e != nil || hw.Unix() < now {
		t.Fatalf("hw=%v e=%v", hw, e)
	}
}
