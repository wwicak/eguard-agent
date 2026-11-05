package bootintegration

import (
	"context"
	"testing"
	"time"
)

func TestRunnerRejectsClockRollbackAfterBuild(t *testing.T) {
	r := newRig(t)
	r.createJournal(t)
	in := r.inputs()
	now := time.Now()
	in.Now = func() (time.Time, error) { return now, nil }
	runner, closeFn, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	// Both samples remain within certificate validity, but time went backwards.
	now = now.Add(-time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = runner(ctx)
	if r.collected.Load() != 0 || r.received.Load() != 0 {
		t.Fatal("rollback allowed collection or transmission")
	}
	now = now.Add(2 * time.Minute)
	retryCtx, retryCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer retryCancel()
	_ = runner(retryCtx)
	if r.collected.Load() != 0 || r.received.Load() != 0 {
		t.Fatal("ambiguous clock silently recovered")
	}
}
