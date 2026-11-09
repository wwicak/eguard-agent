package installtransaction

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fake struct {
	present                                  bool
	path                                     string
	state                                    State
	createErr, startErr, deleteErr, queryErr error
	creates, starts, deletes                 int
	states                                   []State
	readyErr                                 error
	readyCalls                               int
}

func (f *fake) Lookup(context.Context) (Snapshot, error) {
	if f.queryErr != nil {
		return Snapshot{}, f.queryErr
	}
	if !f.present {
		return Snapshot{State: Missing}, nil
	}
	if len(f.states) > 0 {
		f.state = f.states[0]
		f.states = f.states[1:]
	}
	return Snapshot{State: f.state, Binary: f.path}, nil
}
func (f *fake) Create(context.Context) (bool, error) {
	f.creates++
	f.present = true
	f.path = BinaryPath
	f.state = Stopped
	return true, f.createErr
}
func (f *fake) Start(context.Context) error  { f.starts++; return f.startErr }
func (f *fake) Stop(context.Context) error   { f.state = Stopped; f.states = nil; return nil }
func (f *fake) Delete(context.Context) error { f.deletes++; return f.deleteErr }
func (f *fake) Ready(context.Context) error  { f.readyCalls++; return f.readyErr }
func run(f *fake) error {
	ctx, c := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer c()
	return Run(ctx, f, 5*time.Millisecond)
}
func TestCreatedReadyOnlyAfterEvidence(t *testing.T) {
	f := &fake{states: []State{Pending, Running}} // Stopped after Start is an exit (real SCM), see exit_test.go
	if err := run(f); err != nil {
		t.Fatal(err)
	}
	if f.creates != 1 || f.starts != 1 || f.deletes != 0 || f.readyCalls != 1 {
		t.Fatalf("%+v", f)
	}
}
func TestPartialCreationRollback(t *testing.T) {
	f := &fake{createErr: errors.New("partial")}
	if err := run(f); err == nil || f.deletes != 1 {
		t.Fatalf("err %v fake %+v", err, f)
	}
}
func TestStartFailureRollback(t *testing.T) {
	f := &fake{startErr: errors.New("start")}
	if err := run(f); err == nil || f.deletes != 1 {
		t.Fatalf("err %v fake %+v", err, f)
	}
}
func TestTimeoutRollback(t *testing.T) {
	// A hung start stays StartPending on real SCM (Stopped after Start = exit).
	f := &fake{states: []State{Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending, Pending}}
	ctx, c := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer c()
	err := Run(ctx, f, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || f.deletes != 1 {
		t.Fatalf("%v %+v", err, f)
	}
}
func TestCancellationRollback(t *testing.T) {
	f := &fake{}
	ctx, c := context.WithCancel(context.Background())
	c()
	if err := Run(ctx, f, time.Millisecond); !errors.Is(err, context.Canceled) || f.creates != 0 {
		t.Fatalf("%v %+v", err, f)
	}
}
func TestOwnershipMismatchNoMutation(t *testing.T) {
	f := &fake{present: true, path: `C:\Other\edr.exe`, state: Running}
	if err := run(f); !errors.Is(err, ErrExisting) || f.creates+f.starts+f.deletes != 0 {
		t.Fatalf("%v %+v", err, f)
	}
}
func TestOwnedExistingUpgradeRefused(t *testing.T) {
	f := &fake{present: true, path: BinaryPath, state: Running}
	if err := run(f); !errors.Is(err, ErrExisting) || f.deletes != 0 {
		t.Fatalf("%v %+v", err, f)
	}
}
func TestRollbackFailureReported(t *testing.T) {
	f := &fake{startErr: errors.New("start"), deleteErr: errors.New("delete")}
	err := run(f)
	if err == nil || !strings.Contains(err.Error(), "start") || !strings.Contains(err.Error(), "delete") {
		t.Fatal(err)
	}
}
func TestReadinessFailureRollsBack(t *testing.T) {
	f := &fake{states: []State{Running}, readyErr: errors.New("factory unavailable")}
	err := Run(context.Background(), f, time.Millisecond)
	if err == nil || f.deletes != 1 || f.readyCalls != 1 {
		t.Fatalf("%v %+v", err, f)
	}
}
func TestLookupFailureDoesNotMutate(t *testing.T) {
	f := &fake{queryErr: errors.New("access denied")}
	if err := run(f); err == nil || f.creates+f.starts+f.deletes != 0 {
		t.Fatalf("%v %+v", err, f)
	}
}
func TestNilAdapterRefused(t *testing.T) {
	var f *fake
	if err := Run(context.Background(), nil, time.Millisecond); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("%v %+v", err, f)
	}
}
