// Package journal provides mechanical durable replay and cleanup intent storage.
// Callers MUST verify signed envelope bytes and binding BEFORE acceptance; this package
// cannot authorize cleanup or derive trusted identity. Never expose as a service API.
package journal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucket = []byte("journal-v3")

// maxHistory bounds the append-only chain. A full history fails closed; never evict the anchor.
const maxHistory = 32

var key = []byte("state")
var ErrInvalid = errors.New("journal invalid, missing, or incompatible")

type Binding struct {
	Device     string `json:"device"`
	Tenant     string `json:"tenant"`
	Site       string `json:"site"`
	Enrollment string `json:"enrollment"`
}

// AcceptedRecord retains the original bytes, not a reserialized grant.
// AcceptedAt is caller-provided evidence only; the journal cannot establish trust in a clock.
type AcceptedRecord struct {
	Revision   uint64 `json:"revision"`
	Envelope   []byte `json:"envelope"`
	AcceptedAt int64  `json:"accepted_at"`
}
type CleanupRecord struct {
	AcceptedRecord
	IntentID          string `json:"intent_id"`
	LifecycleRevision uint64 `json:"lifecycle_revision"`
}
type Snapshot struct {
	Version        uint32           `json:"version"`
	Binding        Binding          `json:"binding"`
	Revision       uint64           `json:"revision"`
	Lifecycle      AcceptedRecord   `json:"lifecycle"`
	History        []AcceptedRecord `json:"history"`
	Cleanup        CleanupRecord    `json:"cleanup"`
	CleanupPending bool             `json:"pending"`
	CleanupDone    bool             `json:"done"`
	Nonces         []string         `json:"nonces"`
}
type LifecycleTransition struct {
	ExpectedRevision uint64
	Revision         uint64
	Nonce            string
	Envelope         []byte
	AcceptedAt       int64
	BeforeCommit     func() error // fault injection for isolated tests only; not authorization
}
type CleanupTransition struct {
	ExpectedRevision  uint64
	Revision          uint64
	LifecycleRevision uint64
	Nonce             string
	IntentID          string
	Envelope          []byte
	AcceptedAt        int64
	BeforeCommit      func() error // fault injection for isolated tests only
}
type Store struct {
	db      *bolt.DB
	binding Binding
}

func valid(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
func validBinding(b Binding) bool {
	return valid(b.Device) && valid(b.Tenant) && valid(b.Site) && valid(b.Enrollment)
}
func dbOpen(path string, openFile func(string, int, os.FileMode) (*os.File, error)) (*bolt.DB, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	return bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second, NoSync: false, OpenFile: openFile})
}
func regularFile(path string, flags int, mode os.FileMode, minSize int64) (*os.File, error) {
	// Reject links, directories and path replacement between lstat and open.
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Size() < minSize {
		return nil, ErrInvalid
	}
	f, e := openRegular(path, flags, mode)
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || after.Size() < minSize || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrInvalid
	}
	return f, nil
}

// Platform openRegular rejects symlink/reparse point traversal for final component.
func noCreateOpen(path string, flags int, mode os.FileMode) (*os.File, error) {
	return regularFile(path, flags&^os.O_CREATE, mode, 4096)
}
func openExisting(path string, b Binding, opener func(string, int, os.FileMode) (*os.File, error)) (*Store, error) {
	if !validBinding(b) {
		return nil, ErrInvalid
	}
	if opener == nil {
		opener = noCreateOpen
	}
	db, e := dbOpen(path, opener)
	if e != nil {
		return nil, e
	}
	s := &Store{db, b}
	_, e = s.Read()
	if e == nil {
		e = db.View(func(tx *bolt.Tx) error { return drainCheck(tx.Check()) })
	}
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func drainCheck(ch <-chan error) error {
	var first error
	for e := range ch {
		if e != nil && first == nil {
			first = e
		}
	}
	return first
}

// Create is exclusively for validated initial enrollment. Never use it as repair.
func Create(path string, b Binding) (*Store, error) {
	if !validBinding(b) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	original, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := dbOpen(path, func(path string, flags int, mode os.FileMode) (*os.File, error) {
		opened, e := regularFile(path, flags&^os.O_CREATE, mode, 0)
		if e != nil {
			return nil, e
		}
		info, e := opened.Stat()
		if e != nil || !info.Mode().IsRegular() || !os.SameFile(original, info) || info.Size() != 0 {
			opened.Close()
			return nil, ErrInvalid
		}
		return opened, nil
	})
	if err != nil {
		return nil, err
	}
	s := &Store{db, b}
	err = db.Update(func(tx *bolt.Tx) error {
		bk, e := tx.CreateBucket(bucket)
		if e != nil {
			return e
		}
		return put(bk, Snapshot{Version: 3, Binding: b})
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Open never creates or resets state, and rejects damaged or missing records.
func Open(path string, b Binding) (*Store, error) { return openExisting(path, b, nil) }
func (s *Store) Close() error                     { return s.db.Close() }
func encode(p Snapshot) ([]byte, error) {
	payload, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	if len(payload) > 256*1024 {
		return nil, ErrInvalid
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	return buf, nil
}
func decode(raw []byte, b Binding) (Snapshot, error) {
	var p Snapshot
	if len(raw) < 4 || len(raw) > 256*1024+4 || int(binary.BigEndian.Uint32(raw[:4])) != len(raw)-4 {
		return p, ErrInvalid
	}
	if err := uniqueJSON(raw[4:]); err != nil {
		return Snapshot{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw[4:]))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || p.Version != 3 || p.Binding != b || !validBinding(p.Binding) || p.CleanupPending && p.CleanupDone || len(p.Nonces) > 4096 || len(p.History) > maxHistory || len(p.Lifecycle.Envelope) > 65536 || len(p.Cleanup.Envelope) > 65536 {
		return Snapshot{}, ErrInvalid
	}
	if e := dec.Decode(new(any)); e != io.EOF {
		return Snapshot{}, ErrInvalid
	}
	if p.Revision == 0 {
		if len(p.Nonces) != 0 || len(p.History) != 0 || p.Lifecycle.Revision != 0 || len(p.Lifecycle.Envelope) != 0 || p.Lifecycle.AcceptedAt != 0 || p.Cleanup.Revision != 0 || len(p.Cleanup.Envelope) != 0 || p.Cleanup.AcceptedAt != 0 || p.Cleanup.IntentID != "" || p.Cleanup.LifecycleRevision != 0 || p.CleanupPending || p.CleanupDone {
			return Snapshot{}, ErrInvalid
		}
	} else {
		if p.Lifecycle.Revision == 0 || p.Lifecycle.Revision > p.Revision || len(p.Lifecycle.Envelope) == 0 || p.Lifecycle.AcceptedAt <= 0 || len(p.Nonces) == 0 || uint64(len(p.Nonces)) > p.Revision || (p.Cleanup.Revision == 0 && p.Lifecycle.Revision != p.Revision) {
			return Snapshot{}, ErrInvalid
		}
		if len(p.History) == 0 || len(p.History) > len(p.Nonces) || p.History[len(p.History)-1].Revision != p.Lifecycle.Revision || p.History[len(p.History)-1].AcceptedAt != p.Lifecycle.AcceptedAt || !bytes.Equal(p.History[len(p.History)-1].Envelope, p.Lifecycle.Envelope) {
			return Snapshot{}, ErrInvalid
		}
		for i, record := range p.History {
			if record.Revision == 0 || record.Revision > p.Revision || record.AcceptedAt <= 0 || len(record.Envelope) == 0 || len(record.Envelope) > 65536 {
				return Snapshot{}, ErrInvalid
			}
			if i > 0 && (record.Revision <= p.History[i-1].Revision || record.AcceptedAt < p.History[i-1].AcceptedAt) {
				return Snapshot{}, ErrInvalid
			}
		}
		if p.Cleanup.Revision != 0 {
			if p.Cleanup.Revision != p.Revision || p.Cleanup.LifecycleRevision != p.Lifecycle.Revision || !valid(p.Cleanup.IntentID) || len(p.Cleanup.Envelope) == 0 || p.Cleanup.AcceptedAt <= 0 || (!p.CleanupPending && !p.CleanupDone) {
				return Snapshot{}, ErrInvalid
			}
		} else if len(p.Cleanup.Envelope) != 0 || p.Cleanup.AcceptedAt != 0 || p.Cleanup.IntentID != "" || p.Cleanup.LifecycleRevision != 0 || p.CleanupPending || p.CleanupDone {
			return Snapshot{}, ErrInvalid
		}
	}
	seen := make(map[string]struct{}, len(p.Nonces))
	for _, n := range p.Nonces {
		if !valid(n) {
			return Snapshot{}, ErrInvalid
		}
		if _, ok := seen[n]; ok {
			return Snapshot{}, ErrInvalid
		}
		seen[n] = struct{}{}
	}
	return p, nil
}

// uniqueJSON checks every object key, including nested binding, before struct decoding.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var parse func() (any, error)
	parse = func() (any, error) {
		tok, e := d.Token()
		if e != nil {
			return nil, e
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return tok, nil
		}
		switch delim {
		case '{':
			keys := map[string]struct{}{}
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				name, ok := k.(string)
				if !ok {
					return nil, ErrInvalid
				}
				if _, ok = keys[name]; ok {
					return nil, ErrInvalid
				}
				keys[name] = struct{}{}
				v, e := parse()
				if e != nil {
					return nil, e
				}
				m[name] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, e := parse()
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	}
	v, e := parse()
	if e != nil {
		return e
	}
	if _, ok := v.(map[string]any); !ok {
		return ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}
func put(b *bolt.Bucket, p Snapshot) error {
	v, e := encode(p)
	if e != nil {
		return e
	}
	return b.Put(key, v)
}
func (s *Store) Read() (Snapshot, error) {
	var p Snapshot
	e := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrInvalid
		}
		var err error
		p, err = decode(b.Get(key), s.binding)
		return err
	})
	return p, e
}

// AcceptLifecycle mechanically commits bytes after a separate trusted caller has
// verified signature, binding, action, acceptance window and clock provenance.
func (s *Store) AcceptLifecycle(t LifecycleTransition) error {
	if t.Revision == 0 || !valid(t.Nonce) || len(t.Envelope) == 0 || len(t.Envelope) > 65536 || t.AcceptedAt <= 0 {
		return ErrInvalid
	}
	return s.update(t.ExpectedRevision, t.Revision, t.Nonce, t.BeforeCommit, func(p *Snapshot) error {
		if len(p.History) >= maxHistory || (len(p.History) > 0 && t.AcceptedAt < p.History[len(p.History)-1].AcceptedAt) {
			return ErrInvalid
		}
		p.Lifecycle = AcceptedRecord{Revision: t.Revision, Envelope: append([]byte(nil), t.Envelope...), AcceptedAt: t.AcceptedAt}
		p.History = append(p.History, p.Lifecycle)
		return nil
	})
}

// AcceptCleanup is a distinct committed intent, NOT permission to run cleanup.
func (s *Store) AcceptCleanup(t CleanupTransition) error {
	if t.Revision == 0 || !valid(t.Nonce) || !valid(t.IntentID) || len(t.Envelope) == 0 || len(t.Envelope) > 65536 || t.AcceptedAt <= 0 || t.LifecycleRevision == 0 {
		return ErrInvalid
	}
	return s.update(t.ExpectedRevision, t.Revision, t.Nonce, t.BeforeCommit, func(p *Snapshot) error {
		if p.Lifecycle.Revision != t.LifecycleRevision {
			return ErrInvalid
		}
		p.Cleanup = CleanupRecord{AcceptedRecord: AcceptedRecord{Revision: t.Revision, Envelope: append([]byte(nil), t.Envelope...), AcceptedAt: t.AcceptedAt}, IntentID: t.IntentID, LifecycleRevision: t.LifecycleRevision}
		p.CleanupPending = true
		return nil
	})
}
func (s *Store) update(expected, revision uint64, nonce string, before func() error, modify func(*Snapshot) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrInvalid
		}
		p, e := decode(b.Get(key), s.binding)
		if e != nil {
			return e
		}
		if expected != p.Revision || revision <= p.Revision || p.CleanupPending || p.CleanupDone || len(p.Nonces) >= 4096 {
			return ErrInvalid
		}
		for _, n := range p.Nonces {
			if n == nonce {
				return ErrInvalid
			}
		}
		// The lifecycle association is checked inside the same writer transaction.
		if p.Lifecycle.Revision != 0 && revision <= p.Lifecycle.Revision {
			return ErrInvalid
		}
		p.Revision = revision
		p.Nonces = append(p.Nonces, nonce)
		if e = modify(&p); e != nil {
			return e
		}
		if p.Cleanup.Revision != 0 && p.Cleanup.LifecycleRevision != p.Lifecycle.Revision {
			return ErrInvalid
		}
		if before != nil {
			if e = before(); e != nil {
				return e
			}
		}
		return put(b, p)
	})
}

// MarkCleanupDone requires the exact committed intent and enrollment identity.
func (s *Store) MarkCleanupDone(intentID, enrollment string) error {
	if !valid(intentID) || enrollment != s.binding.Enrollment {
		return ErrInvalid
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrInvalid
		}
		p, e := decode(b.Get(key), s.binding)
		if e != nil {
			return e
		}
		if p.Cleanup.IntentID != intentID || p.Cleanup.Revision == 0 {
			return ErrInvalid
		}
		if p.CleanupDone {
			return nil
		}
		if !p.CleanupPending {
			return ErrInvalid
		}
		p.CleanupPending = false
		p.CleanupDone = true
		return put(b, p)
	})
}
