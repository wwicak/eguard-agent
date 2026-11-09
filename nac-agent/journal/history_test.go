package journal

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func historyStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db")
	s, e := Create(path, bound)
	if e != nil {
		t.Fatal(e)
	}
	return s, path
}
func acceptHistory(t *testing.T, s *Store, expected, revision uint64, at int64, env []byte) {
	t.Helper()
	if e := s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: expected, Revision: revision, Nonce: "history-" + string(rune('A'+revision)), Envelope: env, AcceptedAt: at}); e != nil {
		t.Fatal(e)
	}
}
func TestHistoryReopenCleanupAndDefensiveCopies(t *testing.T) {
	s, path := historyStore(t)
	first := []byte("unsigned initial anchor")
	second := []byte("unsigned renew")
	acceptHistory(t, s, 0, 1, accepted, first)
	acceptHistory(t, s, 1, 3, accepted+1, second)
	if e := s.AcceptCleanup(CleanupTransition{ExpectedRevision: 3, Revision: 4, LifecycleRevision: 3, Nonce: "cleanup", IntentID: "intent", Envelope: []byte("unsigned auth"), AcceptedAt: accepted + 2}); e != nil {
		t.Fatal(e)
	}
	first[0] = 'X'
	second[0] = 'X'
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := Open(path, bound)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	if p.Version != 3 || p.Revision != 4 || len(p.History) != 2 || p.History[0].Revision != 1 || p.History[1].Revision != 3 || p.History[0].AcceptedAt != accepted || p.History[1].AcceptedAt != accepted+1 || !bytes.Equal(p.History[0].Envelope, []byte("unsigned initial anchor")) || !bytes.Equal(p.History[1].Envelope, []byte("unsigned renew")) || !bytes.Equal(p.History[1].Envelope, p.Lifecycle.Envelope) || !p.CleanupPending {
		t.Fatalf("history lost on cleanup: %+v", p)
	}
	p.History[0].Envelope[0] = 'X'
	p.History[1].Envelope[0] = 'X'
	p.History[0] = AcceptedRecord{}
	p.Lifecycle.Envelope[0] = 'X'
	again, e := s.Read()
	if e != nil {
		t.Fatal(e)
	}
	if again.History[0].Envelope[0] != 'u' || again.History[1].Envelope[0] != 'u' || again.Lifecycle.Envelope[0] != 'u' {
		t.Fatal("read aliases persisted history")
	}
	if e := s.MarkCleanupDone("intent", bound.Enrollment); e != nil {
		t.Fatal(e)
	}
	again, e = s.Read()
	if e != nil || len(again.History) != 2 || !again.CleanupDone {
		t.Fatal("done discarded anchor", e)
	}
}
func TestHistoryCASCapacityAndRollback(t *testing.T) {
	s, path := historyStore(t)
	defer s.Close()
	acceptHistory(t, s, 0, 1, accepted, []byte("anchor"))
	if e := s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 1, Revision: 2, Nonce: "failed", Envelope: []byte("fail"), AcceptedAt: accepted + 1, BeforeCommit: func() error { return os.ErrPermission }}); e == nil {
		t.Fatal("fault accepted")
	}
	p, _ := s.Read()
	if len(p.History) != 1 || len(p.Nonces) != 1 {
		t.Fatal("failed tx mutated history")
	}
	if e := s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 1, Revision: 2, Nonce: "backward-time", Envelope: []byte("bad"), AcceptedAt: accepted - 1}); e == nil {
		t.Fatal("backward acceptance time accepted")
	}
	if e := s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 1, Revision: 2, Nonce: "too-big", Envelope: bytes.Repeat([]byte("x"), 65537), AcceptedAt: accepted}); e == nil {
		t.Fatal("oversized envelope accepted")
	}
	var wg sync.WaitGroup
	wins := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wins <- s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: 1, Revision: 2, Nonce: "race", Envelope: []byte("winner"), AcceptedAt: accepted + 1}) == nil
		}()
	}
	wg.Wait()
	close(wins)
	n := 0
	for won := range wins {
		if won {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("CAS winners=%d", n)
	}
	for i := uint64(3); i <= maxHistory; i++ {
		acceptHistory(t, s, i-1, i, accepted+int64(i), []byte("small"))
	}
	before, _ := s.Read()
	if len(before.History) != maxHistory {
		t.Fatal("history not at cap")
	}
	if e := s.AcceptLifecycle(LifecycleTransition{ExpectedRevision: maxHistory, Revision: maxHistory + 1, Nonce: "beyond", Envelope: []byte("no"), AcceptedAt: accepted + 100}); e == nil {
		t.Fatal("evicted anchor/capacity accepted")
	}
	after, _ := s.Read()
	if after.Revision != before.Revision || len(after.Nonces) != len(before.Nonces) || len(after.History) != maxHistory || !bytes.Equal(after.History[0].Envelope, []byte("anchor")) {
		t.Fatal("capacity failure not atomic")
	}
	s.Close()
	s, e := Open(path, bound)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	after, e = s.Read()
	if e != nil || len(after.History) != maxHistory {
		t.Fatal("reopen capacity", e)
	}
}
func TestHistoryCorruptionAndUnsupportedSchema(t *testing.T) {
	cases := map[string]func(*Snapshot){"missing": func(p *Snapshot) { p.History = nil }, "latest mismatch": func(p *Snapshot) { p.Lifecycle.Envelope = []byte("different") }, "history bytes mismatch": func(p *Snapshot) { p.History[0].Envelope = []byte("different") }, "empty envelope": func(p *Snapshot) { p.History[0].Envelope = nil }, "duplicate revision": func(p *Snapshot) { p.History = append(p.History, p.History[0]) }, "time reversal": func(p *Snapshot) {
		p.History = append(p.History, AcceptedRecord{Revision: 2, AcceptedAt: accepted - 1, Envelope: []byte("later")})
		p.Lifecycle = p.History[1]
		p.Revision = 2
		p.Nonces = append(p.Nonces, "nonce2")
	}, "unsupported version": func(p *Snapshot) { p.Version = 99 }, "excess entries": func(p *Snapshot) {
		for i := 1; i <= maxHistory; i++ {
			p.History = append(p.History, AcceptedRecord{Revision: uint64(i + 1), AcceptedAt: accepted + int64(i), Envelope: []byte("x")})
			p.Nonces = append(p.Nonces, "nonce"+string(rune(i+65)))
		}
		p.Lifecycle = p.History[len(p.History)-1]
		p.Revision = p.Lifecycle.Revision
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, path := historyStore(t)
			acceptHistory(t, s, 0, 1, accepted, []byte("anchor"))
			p, e := s.Read()
			if e != nil {
				t.Fatal(e)
			}
			mutate(&p)
			raw, e := encode(p)
			if e != nil {
				t.Fatal(e)
			}
			if e = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(key, raw) }); e != nil {
				t.Fatal(e)
			}
			s.Close()
			if reopened, e := Open(path, bound); e == nil {
				reopened.Close()
				t.Fatal("poisoned history accepted")
			}
			if reset, e := Create(path, bound); e == nil {
				reset.Close()
				t.Fatal("poisoned state reset")
			}
		})
	}
	// Old v2 schema cannot become an empty v3 history by silently changing version.
	s, path := historyStore(t)
	p, _ := s.Read()
	p.Version = 2
	raw, _ := encode(p)
	if e := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(key, raw) }); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if opened, e := Open(path, bound); e == nil {
		opened.Close()
		t.Fatal("legacy accepted")
	}
	data, e := os.ReadFile(path)
	if e != nil || len(data) < 4096 {
		t.Fatal("existing disk missing", e)
	}
}
