package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	"eguard-nac-agent/provision"
)

var b = lifecycle.Binding{Issuer: "iss", DeviceID: "dev", TenantID: "ten", SiteID: "site", EnrollmentID: "enr"}

type fx struct {
	boot, life ed25519.PrivateKey
	lifePub    ed25519.PublicKey
	ca         []byte
}

func newFx(t *testing.T) *fx {
	bootPub, boot, _ := ed25519.GenerateKey(rand.Reader)
	provision.BootstrapPinHex = hex.EncodeToString(bootPub)
	t.Cleanup(func() { provision.BootstrapPinHex = "" })
	lifePub, life, _ := ed25519.GenerateKey(rand.Reader)
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	ca, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	return &fx{boot: boot, life: life, lifePub: lifePub, ca: ca}
}

func (f *fx) bootstrap(binding lifecycle.Binding, key ed25519.PrivateKey) []byte {
	p := []byte(fmt.Sprintf(`{"version":1,"purpose":"eguard-nac-boot-config","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"revision":3,"https_origin":"https://nac.example.test","server_ca_der_b64":%q,"lifecycle_keys":{"k1":%q},"machine_cert_sha256":%q,"journal_path":%q,"interval_seconds":60,"backoff_seconds":5,"collect_timeout_seconds":10,"send_timeout_seconds":10}`,
		binding.Issuer, binding.DeviceID, binding.TenantID, binding.SiteID, binding.EnrollmentID, base64.StdEncoding.EncodeToString(f.ca), base64.StdEncoding.EncodeToString(f.lifePub), hex.EncodeToString(make([]byte, 31))+"01", provision.JournalPath))
	sig := ed25519.Sign(key, append([]byte("eguard-nac-boot-config/v1\x00"), p...))
	return []byte(fmt.Sprintf(`{"version":1,"payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
}

func (f *fx) grant(action string, at int64, key ed25519.PrivateKey) []byte {
	p := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"grant_id":"g-%s","revision":1,"policy_revision":1,"action":%q,"mode":"permanent","issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":null}`,
		b.Issuer, b.DeviceID, b.TenantID, b.SiteID, b.EnrollmentID, action, action, at-1, at-1, at+300, at-1))
	sig := ed25519.Sign(key, append([]byte("eguard-nac-lifecycle/v1\x00"), p...))
	return []byte(fmt.Sprintf(`{"version":1,"key_id":"k1","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
}

func TestInstallVerifiesThenProvisionsActiveJournal(t *testing.T) {
	f := newFx(t)
	root := filepath.Join(t.TempDir(), "eGuard NAC")
	now := time.Now()
	obs, e := Install(root, f.bootstrap(b, f.boot), f.grant("activate", now.Unix(), f.life), now)
	if e != nil {
		t.Fatal(e)
	}
	if obs.State != "active" || obs.Mode != "permanent" {
		t.Fatalf("%+v", obs)
	}
	in, e := provision.Load(root)
	if e != nil || in.State.Binding != b || in.State.DurableFloor != 3 {
		t.Fatalf("%+v %v", in.State, e)
	}
	j, e := journal.Open(filepath.Join(root, "journal.db"), journal.Binding{Device: b.DeviceID, Tenant: b.TenantID, Site: b.SiteID, Enrollment: b.EnrollmentID})
	if e != nil {
		t.Fatal(e)
	}
	got, e := lifecycle.Recover(j, map[string]ed25519.PublicKey{"k1": f.lifePub}, b)
	_ = j.Close()
	if e != nil || got.State != "active" {
		t.Fatalf("%+v %v", got, e)
	}
}

// Nothing may be written unless both the bootstrap and the activation verify.
func TestInstallRejectsBeforeWriting(t *testing.T) {
	f := newFx(t)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cases := map[string]struct{ boot, act []byte }{
		"bootstrap signed by wrong key":  {f.bootstrap(b, otherKey), f.grant("activate", now.Unix(), f.life)},
		"activation signed by wrong key": {f.bootstrap(b, f.boot), f.grant("activate", now.Unix(), otherKey)},
		"not an activation":              {f.bootstrap(b, f.boot), f.grant("revoke", now.Unix(), f.life)},
		"expired activation":             {f.bootstrap(b, f.boot), f.grant("activate", now.Unix()-3600, f.life)},
		"activation for other device":    {f.bootstrap(lifecycle.Binding{Issuer: b.Issuer, DeviceID: "other", TenantID: b.TenantID, SiteID: b.SiteID, EnrollmentID: b.EnrollmentID}, f.boot), f.grant("activate", now.Unix(), f.life)},
		"garbage bootstrap":              {[]byte(`{"version":1}`), f.grant("activate", now.Unix(), f.life)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "eGuard NAC")
			if _, e := Install(root, c.boot, c.act, now); e == nil {
				t.Fatal("accepted")
			}
			if _, e := os.Lstat(root); !os.IsNotExist(e) {
				t.Fatalf("provisioning root written despite rejection: %v", e)
			}
		})
	}
}

func TestInstallRefusesWithoutPin(t *testing.T) {
	f := newFx(t)
	provision.BootstrapPinHex = ""
	root := filepath.Join(t.TempDir(), "eGuard NAC")
	now := time.Now()
	if _, e := Install(root, f.bootstrap(b, f.boot), f.grant("activate", now.Unix(), f.life), now); e == nil {
		t.Fatal("installed without build-time pin")
	}
	if _, e := os.Lstat(root); !os.IsNotExist(e) {
		t.Fatal("root written")
	}
}
