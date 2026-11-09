package bootstrap

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// The shared fixture signs the exact modified bytes with a fresh Ed25519 key;
// none of these cases rely on forging an existing signature.
func adversarialPayload(t *testing.T, f bootFixture, field, value string) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(f.payload(), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m[field]; !ok {
		t.Fatalf("unknown fixture field %q", field)
	}
	m[field] = json.RawMessage(value)
	p, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return f.wrap(p)
}
func TestBootAdversarialStrictNumericTypes(t *testing.T) {
	f := newBootFixture(t)
	for _, tc := range []struct{ field, value string }{
		{"revision", `18446744073709551616`}, {"revision", `-1`}, {"revision", `7.0`}, {"revision", `"7"`}, {"revision", `true`},
		{"interval_seconds", `60.1`}, {"backoff_seconds", `"5"`}, {"send_timeout_seconds", `1e0`},
		{"version", `1.0`},
	} {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			raw := adversarialPayload(t, f, tc.field, tc.value)
			if v, err := Verify(raw, f.public, binding, 7, machineJournal); err == nil {
				t.Fatalf("malformed number accepted: revision=%d", v.Revision())
			}
		})
	}
	// The floor must be compared as uint64, without +1 wraparound. A genuine
	// max-uint64 revision can equal a max-uint64 durable floor.
	raw := adversarialPayload(t, f, "revision", `18446744073709551615`)
	if v, err := Verify(raw, f.public, binding, math.MaxUint64, machineJournal); err != nil || v.Revision() != math.MaxUint64 {
		t.Fatalf("valid uint64 boundary rejected: revision=%d err=%v", v.Revision(), err)
	}
	if _, err := Verify(f.wrap(f.payload()), f.public, binding, math.MaxUint64, machineJournal); err == nil {
		t.Fatal("revision below maximal floor accepted")
	}
}
func TestBootAdversarialCaseNullAndDuplicateKeys(t *testing.T) {
	f := newBootFixture(t)
	p := f.payload()
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"case-alias", bytes.Replace(p, []byte(`"revision":7`), []byte(`"Revision":7`), 1)},
		{"case-duplicate", bytes.Replace(p, []byte(`"revision":7`), []byte(`"revision":7,"Revision":8`), 1)},
		{"null-revision", bytes.Replace(p, []byte(`"revision":7`), []byte(`"revision":null`), 1)},
		{"duplicate-revision", bytes.Replace(p, []byte(`"revision":7`), []byte(`"revision":7,"revision":8`), 1)},
		{"null-key", bytes.Replace(p, []byte(`"lifecycle-1":`), []byte(`"lifecycle-1":null,"shadow":`), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.raw, p) {
				t.Fatal("fixture not changed")
			}
			if _, err := Verify(f.wrap(tc.raw), f.public, binding, 7, machineJournal); err == nil {
				t.Fatal("signed noncanonical payload accepted")
			}
		})
	}
	env := f.wrap(p)
	for name, raw := range map[string][]byte{
		"outer-case":           bytes.Replace(env, []byte(`"version":1`), []byte(`"Version":1`), 1),
		"outer-case-duplicate": bytes.Replace(env, []byte(`"version":1`), []byte(`"version":1,"Version":2`), 1),
		"outer-null":           bytes.Replace(env, []byte(`"version":1`), []byte(`"version":null`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(raw, f.public, binding, 7, machineJournal); err == nil {
				t.Fatal("noncanonical envelope accepted")
			}
		})
	}
}
func TestBootAdversarialCallerPathAliases(t *testing.T) {
	f := newBootFixture(t)
	// Both signed path and purportedly trusted caller path are identical. This
	// tests lexical validation, not filesystem ACL/reparse point resolution.
	for _, path := range []string{
		`C:\ProgramData\eGuardNAC\.\state.db`,
		`C:\ProgramData\eGuardNAC\state.db.`,
		`C:\ProgramData\eGuardNAC\state.db `,
		`C:\ProgramData\eGuardNAC\CON\state.db`,
		`C:\ProgramData\eGuardNAC\state.db:stream`,
		`C:\ProgramData\eGuardNAC\state.db\\`,
	} {
		t.Run(path, func(t *testing.T) {
			quoted, _ := json.Marshal(path)
			p := bytes.Replace(f.payload(), []byte(`"journal_path":"C:\\ProgramData\\eGuardNAC\\state.db"`), []byte(`"journal_path":`+string(quoted)), 1)
			if bytes.Equal(p, f.payload()) {
				t.Fatal("fixture path replacement failed")
			}
			if _, err := Verify(f.wrap(p), f.public, binding, 7, path); err == nil {
				t.Fatal("unsafe caller-supplied Windows path accepted")
			}
		})
	}
	// Windows namespace prefixes must not be interpreted as ordinary drive paths.
	for _, path := range []string{`\\?\C:\ProgramData\eGuardNAC\state.db`, `\\.\C:\ProgramData\eGuardNAC\state.db`, `C:\CON\state.db`} {
		t.Run(path, func(t *testing.T) {
			quoted, _ := json.Marshal(path)
			p := bytes.Replace(f.payload(), []byte(`"journal_path":"C:\\ProgramData\\eGuardNAC\\state.db"`), []byte(`"journal_path":`+string(quoted)), 1)
			if bytes.Equal(p, f.payload()) {
				t.Fatal("fixture path replacement failed")
			}
			if _, err := Verify(f.wrap(p), f.public, binding, 7, path); err == nil {
				t.Fatal("device path accepted")
			}
		})
	}
}
func TestBootAdversarialMalformedOrigin(t *testing.T) {
	f := newBootFixture(t)
	for _, origin := range []string{
		"https://nac.example.test:abc", "https://nac.example.test:0", "https://nac.example.test:65536",
		"https://nac.example.test:", "https://bad_host.test",
		"https://nac.example.test%00.evil.test",
	} {
		t.Run(origin, func(t *testing.T) {
			raw := adversarialPayload(t, f, "https_origin", stringMustJSON(t, origin))
			if _, err := Verify(raw, f.public, binding, 7, machineJournal); err == nil {
				t.Fatal("malformed origin accepted")
			}
		})
	}
}
func stringMustJSON(t *testing.T, s string) string {
	t.Helper()
	b, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestBootAdversarialZeroVerifiedCannotBeAuthority(t *testing.T) {
	var v Verified
	// A zero value is constructible by any Go caller. These getters should not
	// panic; absence of an IsValid/checked constructor is a caller integration
	// gate, not evidence Verify accepted an unsigned config.
	if v.Revision() != 0 || v.Origin() != "" || v.JournalPath() != "" || len(v.ServerCADER()) != 0 || len(v.LifecycleKeys()) != 0 {
		t.Fatal("zero Verified unexpectedly has authority")
	}
	if strings.TrimSpace(v.Binding().DeviceID) != "" {
		t.Fatal("zero Verified has device binding")
	}
}
