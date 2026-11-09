package bootintegration

import (
	"testing"
	"time"
)

func TestBootRejectsCredentialOutsideTrustedValidity(t *testing.T) {
	for _, delta := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		t.Run(delta.String(), func(t *testing.T) {
			r := newRig(t)
			r.createJournal(t)
			in := r.inputs()
			in.Now = func() (time.Time, error) { return time.Now().Add(delta), nil }
			runner, closeFn, err := Build(in)
			if closeFn != nil {
				defer closeFn()
			}
			if err == nil || runner != nil {
				t.Fatal("credential accepted outside trusted validity")
			}
			if r.collected.Load() != 0 || r.received.Load() != 0 {
				t.Fatal("side effects on failed startup")
			}
			if r.resolved.Load() && r.acquired.n.Load() != 1 {
				t.Fatal("credential resource leaked")
			}
		})
	}
}
