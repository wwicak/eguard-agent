// Package provision holds installer-owned, public boot inputs. It is not a trusted clock or anti-rollback hardware.
package provision

import (
	"bytes"
	"crypto/ed25519"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const BootstrapFile = "bootstrap.json"
const StateFile = "state.json"

// BootstrapPinHex is set at link time with -X eguard-nac-agent/provision.BootstrapPinHex=<64 lowercase hex digits>.
var BootstrapPinHex string
var mu sync.Mutex
var ErrInvalid = errors.New("provision: invalid or untrusted state")

func Pin() (ed25519.PublicKey, error) {
	if len(BootstrapPinHex) != 64 || strings.ToLower(BootstrapPinHex) != BootstrapPinHex {
		return nil, ErrInvalid
	}
	p, e := hex.DecodeString(BootstrapPinHex)
	if e != nil || len(p) != ed25519.PublicKeySize || bytes.Equal(p, make([]byte, 32)) {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(p), nil
}

type State struct {
	Version      uint32            `json:"version"`
	Binding      lifecycle.Binding `json:"binding"`
	DurableFloor uint64            `json:"durable_floor"`
	JournalPath  string            `json:"journal_path"`
	Replace      bool              `json:"-"`
}
type Inputs struct {
	State          State
	BootstrapBytes []byte
	BootstrapPin   ed25519.PublicKey
}

func strict(d *json.Decoder, depth int) error {
	if depth > 4 {
		return ErrInvalid
	}
	t, e := d.Token()
	if e != nil || t == nil {
		return ErrInvalid
	}
	if delim, ok := t.(json.Delim); ok {
		if delim != '{' {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			s, ok := k.(string)
			if e != nil || !ok || seen[s] {
				return ErrInvalid
			}
			seen[s] = true
			if e = strict(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	}
	return nil
}
func exact(raw []byte, fields ...string) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if strict(d, 0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) != len(fields) {
		return ErrInvalid
	}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			return ErrInvalid
		}
	}
	return nil
}
func validBinding(b lifecycle.Binding) bool {
	for _, s := range []string{b.Issuer, b.DeviceID, b.TenantID, b.SiteID, b.EnrollmentID} {
		if len(s) == 0 || len(s) > 128 {
			return false
		}
		for _, r := range s {
			if r < 33 || r > 126 {
				return false
			}
		}
	}
	return true
}
func validState(s State) bool {
	return s.Version == 1 && s.DurableFloor > 0 && s.JournalPath == JournalPath && validBinding(s.Binding)
}
func decodeState(raw []byte) (State, error) {
	var s State
	if len(raw) == 0 || len(raw) > 4096 || exact(raw, "version", "binding", "durable_floor", "journal_path") != nil {
		return s, ErrInvalid
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	if exact(m["binding"], "Issuer", "DeviceID", "TenantID", "SiteID", "EnrollmentID") != nil {
		return s, ErrInvalid
	}
	if json.Unmarshal(raw, &s) != nil || !validState(s) {
		return State{}, ErrInvalid
	}
	return s, nil
}
func encodeState(s State) ([]byte, error) {
	if !validState(s) {
		return nil, ErrInvalid
	}
	s.Replace = false
	return json.Marshal(s)
}
func safe(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return ErrInvalid
	}
	return checkPath(root)
}
func read(root, name string, max int) ([]byte, error) {
	p := filepath.Join(root, name)
	if e := checkPath(p); e != nil {
		return nil, e
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > int64(max) {
		return nil, ErrInvalid
	}
	data, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(data) > max {
		return nil, ErrInvalid
	}
	return data, nil
}

// LoadConfig is Load without opening the journal. Use it while the service is
// running (it holds journal.db exclusively); all path/ACL checks still apply and
// the returned bootstrap must still be verified with bootstrap.Verify.
func LoadConfig(root string) (Inputs, error) {
	var out Inputs
	if e := safe(root); e != nil {
		return out, fmt.Errorf("provision root: %w", e)
	}
	pin, e := PinForRoot(root)
	if e != nil {
		return out, fmt.Errorf("provision pin: %w", e)
	}
	raw, e := read(root, StateFile, 4096)
	if e != nil {
		return out, fmt.Errorf("provision state: %w", e)
	}
	s, e := decodeState(raw)
	if e != nil {
		return out, e
	}
	raw, e = read(root, BootstrapFile, 256*1024)
	if e != nil || len(raw) == 0 {
		return out, fmt.Errorf("provision bootstrap: %w", ErrInvalid)
	}
	return Inputs{State: s, BootstrapBytes: raw, BootstrapPin: pin}, nil
}

func Load(root string) (Inputs, error) {
	var out Inputs
	if e := safe(root); e != nil {
		return out, fmt.Errorf("provision root: %w", e)
	}
	pin, e := PinForRoot(root)
	if e != nil {
		return out, fmt.Errorf("provision pin: %w", e)
	}
	raw, e := read(root, StateFile, 4096)
	if e != nil {
		return out, fmt.Errorf("provision state: %w", e)
	}
	s, e := decodeState(raw)
	if e != nil {
		return out, e
	}
	raw, e = read(root, BootstrapFile, 256*1024)
	if e != nil || len(raw) == 0 {
		return out, fmt.Errorf("provision bootstrap: %w", ErrInvalid)
	}
	if e = checkPath(filepath.Join(root, "journal.db")); e != nil {
		return out, fmt.Errorf("provision journal: %w", e)
	}
	j, e := journal.Open(filepath.Join(root, "journal.db"), journalBinding(s.Binding))
	if e != nil {
		return out, fmt.Errorf("provision journal binding: %w", e)
	}
	_ = j.Close()
	out = Inputs{State: s, BootstrapBytes: raw, BootstrapPin: pin}
	return out, nil
}
func atomic(root, name string, data []byte) error {
	f, e := os.CreateTemp(root, ".nac-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = protectFile(f.Name()); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(root, name))
}
func Write(root string, s State, bootstrapBytes []byte) error {
	mu.Lock()
	defer mu.Unlock()
	if _, e := PinForRoot(root); e != nil {
		return e
	}
	data, e := encodeState(s)
	if e != nil || len(bootstrapBytes) == 0 || len(bootstrapBytes) > 256*1024 {
		return ErrInvalid
	}
	if e = prepareRoot(root); e != nil {
		return e
	}
	existing, e := read(root, StateFile, 4096)
	if e == nil {
		old, err := decodeState(existing)
		if err != nil {
			return err
		}
		if s.DurableFloor < old.DurableFloor {
			return ErrInvalid
		}
		if !s.Replace || s.Binding != old.Binding {
			return ErrInvalid
		}
		if err = checkPath(filepath.Join(root, "journal.db")); err != nil {
			return err
		}
		j, err := journal.Open(filepath.Join(root, "journal.db"), journalBinding(old.Binding))
		if err != nil {
			return err
		}
		_ = j.Close()
	} else if !os.IsNotExist(e) {
		return e
	} else {
		j, err := journal.Create(filepath.Join(root, "journal.db"), journalBinding(s.Binding))
		if err != nil {
			return err
		}
		if err = j.Close(); err != nil {
			return err
		}
		if err = protectFile(filepath.Join(root, "journal.db")); err != nil {
			return err
		}
	}
	if e = atomic(root, BootstrapFile, bootstrapBytes); e != nil {
		return e
	}
	return atomic(root, StateFile, data)
}
func journalBinding(b lifecycle.Binding) journal.Binding {
	return journal.Binding{Device: b.DeviceID, Tenant: b.TenantID, Site: b.SiteID, Enrollment: b.EnrollmentID}
}
func RaiseFloor(root string, revision uint64) error {
	mu.Lock()
	defer mu.Unlock()
	if e := safe(root); e != nil {
		return e
	}
	raw, e := read(root, StateFile, 4096)
	if e != nil {
		return e
	}
	s, e := decodeState(raw)
	if e != nil {
		return e
	}
	if revision < s.DurableFloor || revision == 0 {
		return ErrInvalid
	}
	if revision == s.DurableFloor {
		return nil
	}
	s.DurableFloor = revision
	raw, e = encodeState(s)
	if e != nil {
		return e
	}
	return atomic(root, StateFile, raw)
}
