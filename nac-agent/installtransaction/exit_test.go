package installtransaction

import (
	"errors"
	"testing"
)

// Observed on real SCM (Windows 10 tester): after a successful StartService the
// service exited (event 7024) and SCM reported Stopped; the transaction kept
// polling until its deadline instead of failing. A Stopped observation after a
// successful Start means the service process terminated and must fail fast.
func TestServiceExitAfterStartFailsFast(t *testing.T) {
	f := &fake{states: []State{Pending, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped, Stopped}}
	err := run(f)
	if !errors.Is(err, ErrServiceExited) {
		t.Fatalf("want ErrServiceExited, got %v", err)
	}
	if f.readyCalls != 0 || f.deletes != 1 {
		t.Fatalf("exited service must roll back without readiness: %+v", f)
	}
}
