package bootintegration

import (
	"context"
	"crypto/x509"
	"testing"
	"time"
)

func TestRunnerRefusesExpiredCredentialBeforeCollection(t *testing.T) {
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
	leaf, err := x509.ParseCertificate(r.leaf)
	if err != nil {
		t.Fatal(err)
	}
	now = leaf.NotAfter.Add(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = runner(ctx)
	if r.collected.Load() != 0 || r.received.Load() != 0 {
		t.Fatal("expired credential allowed collection or transmission")
	}
}
