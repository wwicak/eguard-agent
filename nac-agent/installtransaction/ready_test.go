package installtransaction

import (
	"context"
	"errors"
	"testing"
	"time"
)

// servicehost reports SCM Running only AFTER the verified factory succeeded
// (signed bootstrap, ACL-checked provisioning, journal, CNG credential). Readiness
// evidence = the service reaches Running and STAYS Running for a stability window
// (a factory failure or crash moves it to Stopped within that window).
func TestStableRunningRequiresWholeWindow(t *testing.T) {
	seq := []State{Running, Running, Running, Running, Running, Running}
	i := 0
	lookup := func(context.Context) (Snapshot, error) {
		s := seq[i]
		if i < len(seq)-1 {
			i++
		}
		return Snapshot{State: s, Binary: BinaryPath}, nil
	}
	if e := stableRunning(context.Background(), lookup, 30*time.Millisecond, 5*time.Millisecond); e != nil {
		t.Fatal(e)
	}
}

func TestStableRunningRejectsExitInsideWindow(t *testing.T) {
	seq := []State{Running, Running, Stopped}
	i := 0
	lookup := func(context.Context) (Snapshot, error) {
		s := seq[i]
		if i < len(seq)-1 {
			i++
		}
		return Snapshot{State: s, Binary: BinaryPath}, nil
	}
	if e := stableRunning(context.Background(), lookup, 50*time.Millisecond, 5*time.Millisecond); !errors.Is(e, ErrServiceExited) {
		t.Fatalf("got %v", e)
	}
}

func TestStableRunningRejectsForeignBinaryAndLookupError(t *testing.T) {
	foreign := func(context.Context) (Snapshot, error) { return Snapshot{State: Running, Binary: `C:\x.exe`}, nil }
	if e := stableRunning(context.Background(), foreign, 20*time.Millisecond, 5*time.Millisecond); !errors.Is(e, ErrExisting) {
		t.Fatalf("got %v", e)
	}
	boom := errors.New("scm")
	bad := func(context.Context) (Snapshot, error) { return Snapshot{}, boom }
	if e := stableRunning(context.Background(), bad, 20*time.Millisecond, 5*time.Millisecond); !errors.Is(e, boom) {
		t.Fatalf("got %v", e)
	}
}

func TestStableRunningHonoursCancellation(t *testing.T) {
	ok := func(context.Context) (Snapshot, error) { return Snapshot{State: Running, Binary: BinaryPath}, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := stableRunning(ctx, ok, time.Second, 5*time.Millisecond); !errors.Is(e, context.Canceled) {
		t.Fatalf("got %v", e)
	}
}
