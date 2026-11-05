package cleanup

import (
	"errors"
	"reflect"
	"testing"
)

type fake struct {
	ops  []string
	fail map[string]error
}

func (f *fake) do(op string) error {
	f.ops = append(f.ops, op)
	return f.fail[op]
}
func (f *fake) MarkServiceForDeletion() error { return f.do("service") }
func (f *fake) RemoveMachineCredential(fp [32]byte) error {
	if fp == ([32]byte{}) {
		return errors.New("zero fingerprint")
	}
	return f.do("credential")
}
func (f *fake) RemoveProvisioning() error    { return f.do("provisioning") }
func (f *fake) ScheduleBinaryRemoval() error { return f.do("binary") }

var fp = [32]byte{1}

// Service is marked first so a crash mid-cleanup can never leave a runnable NAC
// service; provisioning (the evidence of enrollment) is removed after the
// credential; binaries are scheduled last because they are in use.
func TestOrderAndCompleteness(t *testing.T) {
	f := &fake{}
	if e := Run(f, fp); e != nil {
		t.Fatal(e)
	}
	want := []string{"service", "credential", "provisioning", "binary"}
	if !reflect.DeepEqual(f.ops, want) {
		t.Fatalf("ops=%v want %v", f.ops, want)
	}
}

// Every step is attempted even when an earlier one fails (best-effort, idempotent),
// and all failures are reported; nothing is silently swallowed.
func TestContinuesAndReportsAllFailures(t *testing.T) {
	e1, e2 := errors.New("svc busy"), errors.New("cert locked")
	f := &fake{fail: map[string]error{"service": e1, "credential": e2}}
	err := Run(f, fp)
	if !errors.Is(err, e1) || !errors.Is(err, e2) {
		t.Fatalf("err=%v", err)
	}
	if len(f.ops) != 4 {
		t.Fatalf("steps skipped: %v", f.ops)
	}
}

func TestIdempotentRerun(t *testing.T) {
	f := &fake{}
	_ = Run(f, fp)
	if e := Run(f, fp); e != nil {
		t.Fatal(e)
	}
	if len(f.ops) != 8 {
		t.Fatalf("%v", f.ops)
	}
}

func TestNilAdapterRefused(t *testing.T) {
	if Run(nil, fp) == nil {
		t.Fatal("nil adapter accepted")
	}
}
