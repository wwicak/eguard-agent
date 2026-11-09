package journal

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var bound = Binding{Device: "device-test", Tenant: "tenant-test", Site: "site-test", Enrollment: "enroll-test"}

func TestDurableAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	if _, err := Open(path, bound); err == nil {
		t.Fatal("missing state reopened")
	}
	s, err := Create(path, bound)
	if err != nil {
		t.Fatal(err)
	}
	env := []byte("test-only-unverified-envelope")
	if err = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "nonce-1", Envelope: env, AcceptedAt: accepted}); err != nil {
		t.Fatal(err)
	}
	if err = s.AcceptCleanup(CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 1, Nonce: "nonce-2", IntentID: "intent", Envelope: []byte("unsigned cleanup fixture"), AcceptedAt: accepted}); err != nil {
		t.Fatal(err)
	}
	env[0] = 'X'
	s.Close()
	s, err = Open(path, bound)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 2 || !snap.CleanupPending || !bytes.Equal(snap.Lifecycle.Envelope, []byte("test-only-unverified-envelope")) {
		t.Fatalf("lost committed intent: %+v", snap)
	}
	snap.Lifecycle.Envelope[0] = 'X'
	again, _ := s.Read()
	if again.Lifecycle.Envelope[0] != 't' {
		t.Fatal("mutable read")
	}
	if err = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 2, Revision: 3, Nonce: "nonce-1", Envelope: []byte("test"), AcceptedAt: accepted}); err == nil {
		t.Fatal("nonce replay")
	}
	if err = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 2, Revision: 1, Nonce: "nonce-2", Envelope: []byte("test"), AcceptedAt: accepted}); err == nil {
		t.Fatal("old revision")
	}
	if err = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 2, Revision: 3, Nonce: "nonce-2", Envelope: []byte("test"), AcceptedAt: accepted}); err == nil {
		t.Fatal("pending cleanup allowed new grant")
	}
	if err = s.MarkCleanupDone("intent", bound.Enrollment); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkCleanupDone("intent", bound.Enrollment); err != nil {
		t.Fatal("retry not idempotent", err)
	}
	s.Close()
	s, err = Open(path, bound)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, _ = s.Read()
	if snap.CleanupPending || !snap.CleanupDone {
		t.Fatal("cleanup completion lost")
	}
}
func TestCorruptAndBinding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(p, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, bound); err == nil {
		t.Fatal("corrupt accepted")
	}
	if _, err := Create(p, bound); err == nil {
		t.Fatal("corrupt reset")
	}
	os.Remove(p)
	s, err := Create(p, bound)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	other := bound
	other.Site = "wrong"
	if _, err := Open(p, other); err == nil {
		t.Fatal("rebound")
	}
	if _, err := Create(p, bound); err == nil {
		t.Fatal("existing reset")
	}
}
func TestTruncatedExistingFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	s, e := Create(p, bound)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = os.Truncate(p, 24); e != nil {
		t.Fatal(e)
	}
	if s, e = Open(p, bound); e == nil {
		s.Close()
		t.Fatal("truncated accepted")
	}
	if s, e = Create(p, bound); e == nil {
		s.Close()
		t.Fatal("truncated reset")
	}
}
func TestFailedTransactionNoAcceptance(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	s, err := Create(p, bound)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "x", Envelope: []byte("test"), AcceptedAt: accepted, BeforeCommit: func() error { return os.ErrPermission }}); err == nil {
		t.Fatal("failed commit accepted")
	}
	snap, _ := s.Read()
	if snap.Revision != 0 || snap.CleanupPending {
		t.Fatal("partial write")
	}
	if err = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "x", Envelope: []byte("test"), AcceptedAt: accepted}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(p, bound)
	if err != nil {
		t.Fatal(err)
	}
	snap, err = s.Read()
	if err != nil || snap.CleanupPending || snap.Revision != 1 {
		t.Fatalf("failed-then-committed state not durable: %+v %v", snap, err)
	}
}
func TestProcessWorker(t *testing.T) {
	if os.Getenv("NAC_JOURNAL_WORKER") != "1" {
		return
	}
	s, err := Open(os.Getenv("NAC_JOURNAL_PATH"), bound)
	if err != nil {
		os.Exit(3)
	}
	defer s.Close()
	if s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "shared", Envelope: []byte("test"), AcceptedAt: accepted}) != nil {
		os.Exit(4)
	}
}
func TestConcurrentProcesses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	s, e := Create(p, bound)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := exec.Command(os.Args[0], "-test.run=^TestProcessWorker$")
			c.Env = append(os.Environ(), "NAC_JOURNAL_WORKER=1", "NAC_JOURNAL_PATH="+p)
			results <- c.Run() == nil
		}()
	}
	wg.Wait()
	close(results)
	n := 0
	for v := range results {
		if v {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("accepted %d processes", n)
	}
}
