package servicehost

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestMissingFactoryFailsBeforeRunning(t *testing.T) {
	var running atomic.Int32
	err := Run(nil, make(chan Command), func(s Status) {
		if s == Running {
			running.Add(1)
		}
	})
	if !errors.Is(err, ErrConfigurationRequired) || running.Load() != 0 {
		t.Fatalf("missing factory: %v running=%d", err, running.Load())
	}
}
func TestFactoryFailureDoesNotStartRunner(t *testing.T) {
	var runs atomic.Int32
	err := Run(func() (Runner, error) {
		return func(context.Context) error { runs.Add(1); return nil }, errors.New("unverified boot")
	}, make(chan Command), nil)
	if !errors.Is(err, ErrConfigurationRequired) || runs.Load() != 0 {
		t.Fatalf("factory bypass: %v %d", err, runs.Load())
	}
	err = Run(func() (Runner, error) { return nil, nil }, make(chan Command), nil)
	if !errors.Is(err, ErrConfigurationRequired) {
		t.Fatalf("nil runner: %v", err)
	}
}
func TestSyntheticRunnerStartsAndStopJoins(t *testing.T) {
	commands := make(chan Command, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	cancelSeen := make(chan struct{})
	done := make(chan error, 1)
	statuses := make(chan Status, 16)
	go func() {
		done <- Run(func() (Runner, error) {
			return func(ctx context.Context) error {
				close(entered)
				<-ctx.Done()
				close(cancelSeen)
				<-release
				return ctx.Err()
			}, nil
		}, commands, func(s Status) { statuses <- s })
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("runner not started")
	}
	commands <- Stop
	select {
	case <-cancelSeen:
	case <-time.After(time.Second):
		t.Fatal("runner not canceled")
	}
	select {
	case e := <-done:
		t.Fatalf("returned without join: %v", e)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("did not join")
	}
	var seen []Status
	for len(statuses) > 0 {
		seen = append(seen, <-statuses)
	}
	if len(seen) < 3 || seen[0] != StartPending || seen[1] != Running || seen[2] != StopPending {
		t.Fatalf("statuses: %v", seen)
	}
}
func TestRunnerFailurePropagates(t *testing.T) {
	boom := errors.New("runtime failed")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Run(func() (Runner, error) {
			return func(context.Context) error { close(entered); <-release; return boom }, nil
		}, make(chan Command), nil)
	}()
	<-entered
	close(release)
	select {
	case e := <-done:
		if !errors.Is(e, boom) {
			t.Fatalf("runner failure lost: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("runner failure hung")
	}
}
