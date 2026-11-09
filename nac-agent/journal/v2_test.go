package journal

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

const accepted int64 = 1730000000 // test-only caller timestamp, not trusted clock proof
func TestV2LifecycleAndIntentReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := Create(path, bound)
	if e != nil {
		t.Fatal(e)
	}
	lifecycle := []byte("UNSIGNED fixture lifecycle")
	auth := []byte("UNSIGNED fixture cleanup")
	if e = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "life-1", Envelope: lifecycle, AcceptedAt: accepted}); e != nil {
		t.Fatal(e)
	}
	if e = s.AcceptCleanup(CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 1, Nonce: "auth-1", IntentID: "intent-1", Envelope: auth, AcceptedAt: accepted + 10}); e != nil {
		t.Fatal(e)
	}
	lifecycle[0] = 'X'
	auth[0] = 'X'
	s.Close()
	s, e = Open(path, bound)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	if p.Version != 3 || p.Revision != 2 || !bytes.Equal(p.Lifecycle.Envelope, []byte("UNSIGNED fixture lifecycle")) || p.Lifecycle.AcceptedAt != accepted || p.Lifecycle.Revision != 1 || p.Cleanup.IntentID != "intent-1" || p.Cleanup.LifecycleRevision != 1 || p.Cleanup.AcceptedAt != accepted+10 || !bytes.Equal(p.Cleanup.Envelope, []byte("UNSIGNED fixture cleanup")) || !p.CleanupPending {
		t.Fatalf("lost intent/lifecycle: %+v", p)
	}
	// Storage recovery does not evaluate expired acceptance windows or reaccept a nonce.
	p.Lifecycle.Envelope[0] = 'X'
	p.Cleanup.Envelope[0] = 'X'
	q, _ := s.Read()
	if q.Lifecycle.Envelope[0] != 'U' || q.Cleanup.Envelope[0] != 'U' {
		t.Fatal("aliased bytes")
	}
	if e = s.AcceptCleanup(CleanupTransition{ExpectedRevision: 2, Revision: 3, LifecycleRevision: 1, Nonce: "auth-1", IntentID: "intent-1", Envelope: []byte("retry"), AcceptedAt: accepted + 100000}); e == nil {
		t.Fatal("reaccepted intent")
	}
	if e = s.MarkCleanupDone("wrong", bound.Enrollment); e == nil {
		t.Fatal("wrong intent completed")
	}
	if e = s.MarkCleanupDone("intent-1", "wrong"); e == nil {
		t.Fatal("wrong enrollment completed")
	}
	if e = s.MarkCleanupDone("intent-1", bound.Enrollment); e != nil {
		t.Fatal(e)
	}
	if e = s.MarkCleanupDone("intent-1", bound.Enrollment); e != nil {
		t.Fatal("same completion not idempotent", e)
	}
	s.Close()
	s, e = Open(path, bound)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	q, _ = s.Read()
	if !q.CleanupDone || q.CleanupPending {
		t.Fatal("completion lost")
	}
}
func TestV2CASAndAtomicFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	s, e := Create(p, bound)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "a", Envelope: []byte("unsigned"), AcceptedAt: accepted}); e != nil {
		t.Fatal(e)
	}
	stale := LifecycleTransition{ExpectedRevision: 0, Revision: 2, Nonce: "b", Envelope: []byte("unsigned"), AcceptedAt: accepted}
	if e = s.AcceptLifecycle(stale); e == nil {
		t.Fatal("stale CAS accepted")
	}
	if e = s.AcceptCleanup(CleanupTransition{ExpectedRevision: 0, Revision: 2, LifecycleRevision: 1, Nonce: "b", IntentID: "id", Envelope: []byte("unsigned"), AcceptedAt: accepted}); e == nil {
		t.Fatal("stale cleanup CAS accepted")
	}
	if e = s.AcceptCleanup(CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 999, Nonce: "b", IntentID: "id", Envelope: []byte("unsigned"), AcceptedAt: accepted}); e == nil {
		t.Fatal("wrong lifecycle association accepted")
	}
	if e = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 1, Revision: 2, Nonce: "b", Envelope: []byte("unsigned"), AcceptedAt: accepted, BeforeCommit: func() error { return os.ErrPermission }}); e == nil {
		t.Fatal("failed commit accepted")
	}
	q, _ := s.Read()
	if q.Revision != 1 || q.CleanupPending || len(q.Nonces) != 1 {
		t.Fatal("failed tx consumed nonce")
	}
	if e = s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 1, Revision: 2, Nonce: "b", Envelope: []byte("unsigned"), AcceptedAt: accepted}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	success := make(chan bool, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success <- s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 2, Revision: 3, Nonce: "shared", Envelope: []byte("unsigned"), AcceptedAt: accepted}) == nil
		}()
	}
	wg.Wait()
	close(success)
	n := 0
	for b := range success {
		if b {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("accepted %d concurrent stale transactions", n)
	}
}
func TestV2RejectLegacyAndCorruptVersion(t *testing.T) {
	for _, raw := range []string{
		`{"binding":{"device":"device-test","tenant":"tenant-test","site":"site-test","enrollment":"enroll-test"},"revision":0,"envelope":null,"pending":false,"done":false,"nonces":null}`,
		`{"version":4,"binding":{"device":"device-test","tenant":"tenant-test","site":"site-test","enrollment":"enroll-test"},"revision":0,"nonces":[]}`,
	} {
		p := filepath.Join(t.TempDir(), "db")
		s, e := Create(p, bound)
		if e != nil {
			t.Fatal(e)
		}
		v := make([]byte, 4+len(raw))
		v[0] = byte(len(raw) >> 24)
		v[1] = byte(len(raw) >> 16)
		v[2] = byte(len(raw) >> 8)
		v[3] = byte(len(raw))
		copy(v[4:], raw)
		if e = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(key, v) }); e != nil {
			t.Fatal(e)
		}
		s.Close()
		if s, e = Open(p, bound); e == nil {
			s.Close()
			t.Fatal("old/unknown schema accepted")
		}
		if s, e = Create(p, bound); e == nil {
			s.Close()
			t.Fatal("old schema reset")
		}
	}
}
