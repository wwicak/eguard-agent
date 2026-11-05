package journal

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestOpenFileRaceDoesNotRecreate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	s, e := Create(p, bound)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	// Exercise actual bbolt.Options.OpenFile seam; remove path after Lstat but before open.
	s, e = openExisting(p, bound, func(path string, flag int, mode os.FileMode) (*os.File, error) {
		// bbolt requests O_CREATE; noCreateOpen must strip it before opening.
		_ = os.Remove(path)
		return noCreateOpen(path, flag, mode)
	})
	if e == nil {
		s.Close()
		t.Fatal("removed journal accepted")
	}
	if _, e = os.Lstat(p); !os.IsNotExist(e) {
		t.Fatalf("journal silently recreated: %v", e)
	}
}
func TestRejectAmbiguousPersistedRecords(t *testing.T) {
	base := `{"version":3,"binding":{"device":"device-test","tenant":"tenant-test","site":"site-test","enrollment":"enroll-test"},"revision":1,"lifecycle":{"revision":1,"envelope":"dGVzdA==","accepted_at":1730000000},"history":[{"revision":1,"envelope":"dGVzdA==","accepted_at":1730000000}],"cleanup":{"revision":0,"envelope":null,"accepted_at":0,"intent_id":"","lifecycle_revision":0},"pending":false,"done":false,"nonces":["good"]}`
	for name, raw := range map[string]string{
		"duplicate-top":    strings.Replace(base, `"revision":1`, `"revision":1,"revision":2`, 1),
		"duplicate-nested": strings.Replace(base, `"device":"device-test"`, `"device":"device-test","device":"other"`, 1),
		"trailing":         base + ` {}`,
		"duplicate-nonce":  strings.Replace(base, `["good"]`, `["good","good"]`, 1),
		"invalid-nonce":    strings.Replace(base, `["good"]`, `["bad nonce"]`, 1),
		"empty-nonce":      strings.Replace(base, `["good"]`, `[""]`, 1),
		"missing-nonce":    strings.Replace(base, `["good"]`, `[]`, 1),
		"missing-binding":  strings.Replace(base, `"tenant":"tenant-test",`, "", 1),
		"zero-cleanup":     strings.Replace(strings.Replace(base, `"revision":1`, `"revision":0`, 1), `"pending":false`, `"pending":true`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "db")
			s, e := Create(p, bound)
			if e != nil {
				t.Fatal(e)
			}
			v := make([]byte, 4+len(raw))
			binary.BigEndian.PutUint32(v[:4], uint32(len(raw)))
			copy(v[4:], raw)
			if e = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(key, v) }); e != nil {
				t.Fatal(e)
			}
			s.Close()
			if s, e = Open(p, bound); e == nil {
				s.Close()
				t.Fatal("ambiguous persisted record accepted")
			}
		})
	}
}
func TestCheckDrainCollectsFirstError(t *testing.T) {
	ch := make(chan error, 3)
	ch <- ErrInvalid
	ch <- os.ErrPermission
	ch <- nil
	close(ch)
	if e := drainCheck(ch); e != ErrInvalid {
		t.Fatalf("first error lost: %v", e)
	}
}
