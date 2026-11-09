package bootstrap

// Proposed API (not implemented):
// Verify(raw []byte, pinned ed25519.PublicKey, binding lifecycle.Binding,
//        durableFloor uint64, expectedJournalPath string) (Verified, error)
// Verified exposes only defensive-copy getters Binding(), Revision(), Origin(),
// ServerCADER(), LifecycleKeys(), MachineCertSHA256(), JournalPath(),
// Timing() (interval, backoff, collectTimeout, sendTimeout time.Duration).
// Caller supplies an independently pinned key, binding, monotonic durable floor
// and installation-owned path. No self-trust, journal creation, clock or OS effects.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"eguard-nac-agent/lifecycle"
)

const domain = "eguard-nac-boot-config/v1\x00"
const machineJournal = `C:\ProgramData\eGuardNAC\state.db`

var binding = lifecycle.Binding{Issuer: "issuer-test", DeviceID: "device-test", TenantID: "tenant-test", SiteID: "site-test", EnrollmentID: "enrollment-test"}

type bootFixture struct {
	public       ed25519.PublicKey
	private      ed25519.PrivateKey
	caDER        []byte
	lifecycleKey ed25519.PublicKey
}

func newBootFixture(t *testing.T) bootFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lifecyclePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-boot-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	return bootFixture{pub, priv, der, lifecyclePub}
}
func (f bootFixture) payload() []byte {
	fingerprint := sha256.Sum256([]byte("synthetic-machine-cert"))
	return []byte(fmt.Sprintf(`{"version":1,"purpose":"eguard-nac-boot-config","issuer":"issuer-test","device_id":"device-test","tenant_id":"tenant-test","site_id":"site-test","enrollment_id":"enrollment-test","revision":7,"https_origin":"https://nac.example.test:443","server_ca_der_b64":%q,"lifecycle_keys":{"lifecycle-1":%q},"machine_cert_sha256":%q,"journal_path":%q,"interval_seconds":60,"backoff_seconds":5,"collect_timeout_seconds":12,"send_timeout_seconds":10}`,
		base64.StdEncoding.EncodeToString(f.caDER), base64.StdEncoding.EncodeToString(f.lifecycleKey), hex.EncodeToString(fingerprint[:]), machineJournal))
}
func (f bootFixture) wrap(p []byte) []byte {
	signature := ed25519.Sign(f.private, append([]byte(domain), p...))
	return []byte(fmt.Sprintf(`{"version":1,"payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(signature)))
}
func verify(f bootFixture, p []byte) (Verified, error) {
	return Verify(f.wrap(p), f.public, binding, 7, machineJournal)
}
func reject(t *testing.T, f bootFixture, p []byte) {
	t.Helper()
	if _, err := verify(f, p); err == nil {
		t.Fatal("invalid signed bootstrap accepted")
	}
}

func TestBootVerifiedConsumerInputsAndDefensiveCopies(t *testing.T) {
	f := newBootFixture(t)
	raw := f.wrap(f.payload())
	v, err := Verify(raw, f.public, binding, 7, machineJournal)
	if err != nil {
		t.Fatal(err)
	}
	if v.Revision() != 7 || v.Binding() != binding || v.Origin() != "https://nac.example.test:443" || v.JournalPath() != machineJournal {
		t.Fatal("verified binding/origin/path not available to caller")
	}
	if _, err := x509.ParseCertificate(v.ServerCADER()); err != nil {
		t.Fatal("unusable CA DER")
	}
	if v.MachineCertSHA256() != sha256.Sum256([]byte("synthetic-machine-cert")) {
		t.Fatal("machine certificate fingerprint mismatch")
	}
	keys := v.LifecycleKeys()
	if !bytes.Equal(keys["lifecycle-1"], f.lifecycleKey) {
		t.Fatal("lifecycle key not delivered")
	}
	interval, backoff, collect, send := v.Timing()
	if interval != 60*time.Second || backoff != 5*time.Second || collect != 12*time.Second || send != 10*time.Second {
		t.Fatal("timing not delivered")
	}
	for i := range raw {
		raw[i] = 0
	}
	ca := v.ServerCADER()
	ca[0] ^= 1
	keys["lifecycle-1"][0] ^= 1
	delete(keys, "lifecycle-1")
	if _, err := x509.ParseCertificate(v.ServerCADER()); err != nil || !bytes.Equal(v.LifecycleKeys()["lifecycle-1"], f.lifecycleKey) || v.Binding() != binding {
		t.Fatal("caller changed verified config via aliases")
	}
}
func TestBootRejectsSignaturePinBindingFloorAndTampering(t *testing.T) {
	f := newBootFixture(t)
	p := f.payload()
	raw := f.wrap(p)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, pin := range map[string]ed25519.PublicKey{"untrusted": other, "missing": nil, "short": {1}} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(raw, pin, binding, 7, machineJournal); err == nil {
				t.Fatal("bad external pin accepted")
			}
		})
	}
	changed := bytes.Replace(p, []byte("nac.example.test"), []byte("evil.example.test"), 1)
	mutated := bytes.Replace(raw, []byte(base64.StdEncoding.EncodeToString(p)), []byte(base64.StdEncoding.EncodeToString(changed)), 1)
	if _, err := Verify(mutated, f.public, binding, 7, machineJournal); err == nil {
		t.Fatal("changed signed bytes accepted")
	}
	wrong := binding
	wrong.TenantID = "other"
	if _, err := Verify(raw, f.public, wrong, 7, machineJournal); err == nil {
		t.Fatal("cross tenant binding accepted")
	}
	if _, err := Verify(raw, f.public, binding, 8, machineJournal); err == nil {
		t.Fatal("signed revision below durable floor accepted")
	}
	if _, err := Verify(raw, f.public, binding, 7, `C:\ProgramData\Other\state.db`); err == nil {
		t.Fatal("wrong installation-owned journal path accepted")
	}
}
func TestBootRejectsSchemaAndBounds(t *testing.T) {
	f := newBootFixture(t)
	p := f.payload()
	fingerprint := sha256.Sum256([]byte("synthetic-machine-cert"))
	for name, parts := range map[string][2]string{
		"unknown":               {`"revision":7`, `"revision":7,"extra":1`},
		"duplicate":             {`"revision":7`, `"revision":7,"revision":7`},
		"null":                  {`"https_origin":"https://nac.example.test:443"`, `"https_origin":null`},
		"missing":               {`,"revision":7`, ``},
		"nested duplicate key":  {`"lifecycle_keys":{"lifecycle-1":`, `"lifecycle_keys":{"lifecycle-1":"ignored","lifecycle-1":`},
		"wrong purpose":         {`"purpose":"eguard-nac-boot-config"`, `"purpose":"other"`},
		"invalid CA":            {fmt.Sprintf(`"server_ca_der_b64":%q`, base64.StdEncoding.EncodeToString(f.caDER)), `"server_ca_der_b64":"AA=="`},
		"empty lifecycle keys":  {fmt.Sprintf(`"lifecycle_keys":{"lifecycle-1":%q}`, base64.StdEncoding.EncodeToString(f.lifecycleKey)), `"lifecycle_keys":{}`},
		"zero collect timeout":  {`"collect_timeout_seconds":12`, `"collect_timeout_seconds":0`},
		"huge interval":         {`"interval_seconds":60`, `"interval_seconds":9223372036854775807`},
		"malformed fingerprint": {fmt.Sprintf(`"machine_cert_sha256":%q`, hex.EncodeToString(fingerprint[:])), `"machine_cert_sha256":"00"`},
	} {
		t.Run(name, func(t *testing.T) {
			if !bytes.Contains(p, []byte(parts[0])) {
				t.Fatal("fixture substitution missing")
			}
			reject(t, f, bytes.Replace(p, []byte(parts[0]), []byte(parts[1]), 1))
		})
	}
	for name, raw := range map[string][]byte{
		"outer duplicate":          bytes.Replace(f.wrap(p), []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"outer unknown":            bytes.Replace(f.wrap(p), []byte(`"version":1`), []byte(`"version":1,"extra":1`), 1),
		"outer null":               bytes.Replace(f.wrap(p), []byte(`"signature_b64":`), []byte(`"signature_b64":null,"invalid_alias":`), 1),
		"outer trailing":           append(f.wrap(p), []byte(` {}`)...),
		"oversize":                 []byte(strings.Repeat("x", 256*1024+1)),
		"oversized signed payload": f.wrap([]byte(strings.Repeat("x", 64*1024+1))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(raw, f.public, binding, 7, machineJournal); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
}
func TestBootRejectsUnsafeOriginAndJournalPath(t *testing.T) {
	f := newBootFixture(t)
	p := f.payload()
	for _, origin := range []string{"http://nac.example.test", "https://user:pass@nac.example.test", "https://nac.example.test/path", "https://nac.example.test?x=1", "https://nac.example.test#x", "https://127.0.0.1:443/other"} {
		t.Run(origin, func(t *testing.T) {
			reject(t, f, bytes.Replace(p, []byte("https://nac.example.test:443"), []byte(origin), 1))
		})
	}
	for _, path := range []string{`..\state.db`, `C:\ProgramData\eGuardNAC\..\other.db`, `C:\Windows\Temp\state.db`, `/tmp/state.db`} {
		t.Run(path, func(t *testing.T) {
			quoted, _ := json.Marshal(path)
			reject(t, f, bytes.Replace(p, []byte(fmt.Sprintf(`%q`, machineJournal)), quoted, 1))
		})
	}
}
