package provision

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"eguard-nac-agent/selfenroll"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistedIdentityRoundTripAndTampering(t *testing.T) {
	root := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	id := selfenroll.Identity{Version: 1, CADERB64: base64.StdEncoding.EncodeToString(der), BootstrapPin: hex.EncodeToString(pub)}
	fp, _ := id.Fingerprint()
	if e = WriteIdentity(root, "localhost:443", id, fp); e != nil {
		t.Fatal(e)
	}
	record, e := LoadIdentity(root)
	if e != nil || record.Identity.BootstrapPin != id.BootstrapPin {
		t.Fatalf("round trip: %v", e)
	}
	raw, e := os.ReadFile(filepath.Join(root, IdentityFile))
	if e != nil {
		t.Fatal(e)
	}
	for _, mutation := range []func(*EnrollmentIdentity){func(r *EnrollmentIdentity) { r.Identity.BootstrapPin = hex.EncodeToString(make([]byte, 32)) }, func(r *EnrollmentIdentity) {
		r.Identity.CADERB64 = base64.StdEncoding.EncodeToString([]byte("tampered"))
	}} {
		r := record
		mutation(&r)
		if e = writeIdentityRecord(root, r); e == nil {
			t.Fatal("tampered identity accepted for write")
		}
		corrupt, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, IdentityFile), corrupt, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = LoadIdentity(root); err == nil {
			t.Fatal("tampered persisted identity accepted")
		}
		if BootstrapPinHex == "" {
			if _, err = PinForRoot(root); err == nil {
				t.Fatal("service pin resolver accepted tampering")
			}
		}
	}
	if e = os.WriteFile(filepath.Join(root, IdentityFile), append(raw, []byte("garbage")...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadIdentity(root); e == nil {
		t.Fatal("tampered persisted identity accepted")
	}
}
