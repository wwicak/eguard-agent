package upgrade

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fake struct {
	calls        []string
	fail         string
	rollbackFail string
}

func (f *fake) step(s string) error {
	f.calls = append(f.calls, s)
	if len(f.calls) > 5 && s == f.rollbackFail {
		return errors.New("rollback " + s)
	}
	if s == f.fail {
		return errors.New(s)
	}
	return nil
}
func (f *fake) Preflight() error  { return f.step("preflight") }
func (f *fake) Relax() error      { return f.step("relax") }
func (f *fake) Protect() error    { return f.step("protect") }
func (f *fake) Stop() error       { return f.step("stop") }
func (f *fake) Backup() error     { return f.step("backup") }
func (f *fake) Replace() error    { return f.step("replace") }
func (f *fake) StartReady() error { return f.step("ready") }
func (f *fake) Restore() error    { return f.step("restore") }
func TestFlow(t *testing.T) {
	for _, x := range []struct {
		fail string
		want []string
	}{
		{"", []string{"preflight", "relax", "stop", "backup", "replace", "ready", "protect"}},
		{"preflight", []string{"preflight"}},
		{"relax", []string{"preflight", "relax", "protect"}},
		{"stop", []string{"preflight", "relax", "stop", "protect"}},
		{"backup", []string{"preflight", "relax", "stop", "backup", "ready", "protect"}},
		{"replace", []string{"preflight", "relax", "stop", "backup", "replace", "stop", "restore", "ready", "protect"}},
		{"ready", []string{"preflight", "relax", "stop", "backup", "replace", "ready", "stop", "restore", "ready", "protect"}},
		{"protect", []string{"preflight", "relax", "stop", "backup", "replace", "ready", "protect"}},
	} {
		t.Run(x.fail, func(t *testing.T) {
			f := &fake{fail: x.fail}
			e := Run(f)
			if (e != nil) != (x.fail != "") {
				t.Fatalf("error %v", e)
			}
			if !reflect.DeepEqual(f.calls, x.want) {
				t.Fatalf("got %v want %v", f.calls, x.want)
			}
		})
	}
}

func TestRollbackFailureStillProtects(t *testing.T) {
	for _, step := range []string{"stop", "restore", "ready"} {
		t.Run(step, func(t *testing.T) {
			f := &fake{fail: "replace", rollbackFail: step}
			e := Run(f)
			if e == nil || !strings.Contains(e.Error(), "rollback "+step) {
				t.Fatalf("missing recovery failure: %v", e)
			}
			if f.calls[len(f.calls)-1] != "protect" {
				t.Fatal("protection not restored")
			}
		})
	}
}
