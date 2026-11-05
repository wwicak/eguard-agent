package servicefactory

import (
	"crypto/ed25519"
	"testing"
	"time"

	"eguard-nac-agent/servicehost"
)

// Remote uninstall from the eGuard console: the server attaches the signed,
// device-bound authorize_uninstall grant to the posture acknowledgement. The
// service verifies it, records it in the journal (anti-replay) and runs the
// official cleanup — the same path as a local hand-off.
func TestRemoteUninstallFromServerAcknowledgement(t *testing.T) {
	r := setup(t, false)
	now := time.Now().Unix()
	r.accept(t, "activate", "permanent", 1, now-100, "null", now-50)
	d := r.deps()
	states := make(chan string, 2)
	d.OnTerminal = func(s string, _ [32]byte) error { states <- s; return nil }
	done := make(chan error, 1)
	go func() { done <- servicehost.Run(New(d), make(chan servicehost.Command), nil) }()
	waitDelivery(t, r)
	g := r.envelope("authorize_uninstall", "permanent", 2, now-100, "null", time.Now().Unix(), r.lifeKey)
	r.serverLifecycle.Store(&g)
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("remote uninstall not applied")
	}
	if s := <-states; s != StateCleanupIntent {
		t.Fatalf("state=%s", s)
	}
}

// A forged grant from a compromised/misconfigured server is ignored; the agent
// keeps reporting and never cleans up.
func TestForgedRemoteUninstallIgnored(t *testing.T) {
	r := setup(t, false)
	now := time.Now().Unix()
	r.accept(t, "activate", "permanent", 1, now-100, "null", now-50)
	d := r.deps()
	called := false
	d.OnTerminal = func(string, [32]byte) error { called = true; return nil }
	commands := make(chan servicehost.Command, 1)
	done := make(chan error, 1)
	go func() { done <- servicehost.Run(New(d), commands, nil) }()
	waitDelivery(t, r)
	_, forger, _ := ed25519.GenerateKey(nil)
	g := r.envelope("authorize_uninstall", "permanent", 2, now-100, "null", time.Now().Unix(), forger)
	r.serverLifecycle.Store(&g)
	before := r.received.Load()
	deadline := time.Now().Add(5 * time.Second)
	for r.received.Load() < before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r.received.Load() < before+2 {
		t.Fatal("agent stopped reporting after forged grant")
	}
	commands <- servicehost.Stop
	<-done
	if called {
		t.Fatal("cleanup ran on forged remote grant")
	}
}
