package setupflow

import (
	"errors"
	"reflect"
	"testing"
)

type fake struct {
	ops  []string
	fail map[string]error
}

func (f *fake) step(n string) error       { f.ops = append(f.ops, n); return f.fail[n] }
func (f *fake) Preflight() error          { return f.step("preflight") }
func (f *fake) Enroll() error             { return f.step("enroll") }
func (f *fake) PlaceBinary() error        { return f.step("binary") }
func (f *fake) RegisterEventLog() error   { return f.step("eventlog") }
func (f *fake) InstallService() error     { return f.step("service") }
func (f *fake) ProtectService() error     { return f.step("protect") }
func (f *fake) RemoveService() error      { return f.step("undo-service") }
func (f *fake) RemoveProvisioning() error { return f.step("undo-enroll") }
func (f *fake) RemoveBinary() error       { return f.step("undo-binary") }
func (f *fake) RemoveEventLog() error     { return f.step("undo-eventlog") }

func TestInstallHappyPathOrder(t *testing.T) {
	f := &fake{}
	if e := Install(f); e != nil {
		t.Fatal(e)
	}
	want := []string{"preflight", "enroll", "binary", "eventlog", "service", "protect"}
	if !reflect.DeepEqual(f.ops, want) {
		t.Fatalf("%v", f.ops)
	}
}

// A failed step undoes only what this run already did, in reverse order, and the
// original error is kept. The service step rolls itself back (installtransaction).
func TestInstallRollsBackCompletedStepsInReverse(t *testing.T) {
	for step, undo := range map[string][]string{
		"preflight": nil,
		"enroll":    nil,
		"binary":    {"undo-enroll"},
		"eventlog":  {"undo-binary", "undo-enroll"},
		"service":   {"undo-eventlog", "undo-binary", "undo-enroll"},
		// A created+running service must be removed (stopped/deleted) BEFORE the
		// provisioning it holds open is removed.
		"protect": {"undo-service", "undo-eventlog", "undo-binary", "undo-enroll"},
	} {
		t.Run(step, func(t *testing.T) {
			boom := errors.New(step + " failed")
			f := &fake{fail: map[string]error{step: boom}}
			if e := Install(f); !errors.Is(e, boom) {
				t.Fatalf("err=%v", e)
			}
			var got []string
			for _, o := range f.ops {
				if len(o) > 5 && o[:5] == "undo-" {
					got = append(got, o)
				}
			}
			if !reflect.DeepEqual(got, undo) {
				t.Fatalf("undo=%v want %v", got, undo)
			}
		})
	}
}

// Preflight failure (e.g. existing install, not elevated) must change nothing.
func TestPreflightFailureNoSideEffects(t *testing.T) {
	f := &fake{fail: map[string]error{"preflight": errors.New("exists")}}
	_ = Install(f)
	if len(f.ops) != 1 {
		t.Fatalf("%v", f.ops)
	}
}

func TestUndoErrorsReportedNotHidden(t *testing.T) {
	boom, undoErr := errors.New("service"), errors.New("cannot remove binary")
	f := &fake{fail: map[string]error{"service": boom, "undo-binary": undoErr}}
	e := Install(f)
	if !errors.Is(e, boom) || !errors.Is(e, undoErr) {
		t.Fatalf("%v", e)
	}
}
