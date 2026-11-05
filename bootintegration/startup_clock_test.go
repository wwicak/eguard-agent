package bootintegration

import (
	"testing"
	"time"
)

func TestBuildRejectsRollbackDuringCredentialAcquisition(t *testing.T) {
	r := newRig(t)
	r.createJournal(t)
	in := r.inputs()
	base := time.Now()
	calls := 0
	in.Now = func() (time.Time, error) {
		calls++
		if calls > 1 {
			return base.Add(-time.Minute), nil
		}
		return base, nil
	}
	runner, closeFn, err := Build(in)
	if closeFn != nil {
		defer closeFn()
	}
	if err == nil || runner != nil {
		t.Fatal("startup accepted backwards clock")
	}
	if r.collected.Load() != 0 || r.received.Load() != 0 {
		t.Fatal("startup side effects")
	}
	if r.resolved.Load() && r.acquired.n.Load() != 1 {
		t.Fatal("resource leak")
	}
}
