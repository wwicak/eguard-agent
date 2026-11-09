package selfenroll

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentityFingerprintAndMismatchBeforeRedeem(t *testing.T) {
	var enrollHits int
	var der []byte
	pin := strings.Repeat("01", 32)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nac/enroll" {
			enrollHits++
			t.Error("code sent before identity accepted")
			return
		}
		json.NewEncoder(w).Encode(Identity{Version: 1, CADERB64: base64.StdEncoding.EncodeToString(der), BootstrapPin: pin})
	}))
	defer s.Close()
	der = s.Certificate().Raw
	rawPin, _ := hex.DecodeString(pin)
	sum := sha256.Sum256(append(append([]byte("eguard-nac-identity/v1\x00"), der...), rawPin...))
	fp := hex.EncodeToString(sum[:])
	id, err := FetchIdentity(context.Background(), strings.TrimPrefix(s.URL, "https://"), fp)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := id.Fingerprint(); err != nil || got != fp {
		t.Fatalf("fingerprint %s %v", got, err)
	}
	if _, err = FetchIdentity(context.Background(), strings.TrimPrefix(s.URL, "https://"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("mismatch accepted")
	}
	if enrollHits != 0 {
		t.Fatal("enroll hit")
	}
}

func TestIdentityRejectsInvalidAddress(t *testing.T) {
	for _, host := range []string{"", "https://example.com:443", "user@host:443", "host:443/path", "host", "host:0", "host:65536"} {
		if ValidateServer(host) == nil {
			t.Errorf("accepted %q", host)
		}
	}
}
