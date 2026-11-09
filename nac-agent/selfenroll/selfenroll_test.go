package selfenroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	if c, err := Normalize(" abcde-fghjk "); err != nil || c != "ABCDEFGHJK" {
		t.Fatalf("%q %v", c, err)
	}
	for _, bad := range []string{"", "ABCDE", "ABCDE-FGHJ0", "ABCDE-FGHJK-L"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCleanHostname(t *testing.T) {
	if got := CleanHostname("PC @ office"); got != "PC---office" {
		t.Fatal(got)
	}
	if got := CleanHostname("é"); got != "-" {
		t.Fatal(got)
	}
}

func TestRedeem(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PC-1"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	var gotCode, gotHost string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		gotCode = in["code"]
		gotHost = in["hostname"]
		if in["code"] == "AAAAAAAAAA" {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "bootstrap": "{\"b\":1}", "activation": "{\"a\":1}"})
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	r, err := Redeem(srv.URL, pool, "bcdef-ghjkl", []byte("csr"), "PC-1")
	if err != nil || gotCode != "BCDEFGHJKL" || gotHost != "PC-1" || string(r.Bootstrap) != "{\"b\":1}" || len(r.CertificateDER) == 0 {
		t.Fatalf("%v %q %+v", err, gotCode, r)
	}
	if _, err := Redeem(srv.URL, pool, "AAAAA-AAAAA", []byte("csr"), "PC-1"); err != ErrCode {
		t.Fatalf("rejected code: %v", err)
	}
	// Untrusted server certificate is refused.
	if _, err := Redeem(srv.URL, x509.NewCertPool(), "bcdef-ghjkl", []byte("csr"), "PC-1"); err == nil {
		t.Fatal("untrusted server accepted")
	}
}
