package boundary

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Test the same gate API used by both fixed Windows entry points, not a source-text match.
func TestGateWithoutParentFailsClosed(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	done := make(chan error, 1)
	go func() { done <- AwaitGate(r, 40*time.Millisecond) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ungated child allowed")
		}
	case <-time.After(time.Second):
		t.Fatal("gate timeout did not close read")
	}
}
func TestStartupCancelledNoCollection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := run(ctx, func() *exec.Cmd { called = true; return exec.Command(os.Args[0]) })
	if err == nil || called {
		t.Fatalf("cancelled startup executed: called=%v error=%v", called, err)
	}
}
func TestGateParentClosesWithoutRelease(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	done := make(chan error, 1)
	go func() { done <- AwaitGate(r, time.Second) }()
	w.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("EOF allowed collection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent-close hung")
	}
}
