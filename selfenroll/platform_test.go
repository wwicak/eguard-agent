package selfenroll

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedeemPlatformWireCompatibility(t *testing.T) {
	for _, platform := range []string{"windows", "linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var fields map[string]string
				if e := json.NewDecoder(r.Body).Decode(&fields); e != nil {
					t.Error(e)
				}
				got, present := fields["platform"]
				if platform == "windows" {
					if present {
						t.Error("Windows wire format changed")
					}
				} else if got != platform {
					t.Errorf("platform %q", got)
				}
				w.WriteHeader(http.StatusForbidden)
			}))
			defer s.Close()
			roots := x509.NewCertPool()
			roots.AddCert(s.Certificate())
			_, e := Redeem(s.URL, roots, "ABCDE23456", []byte("csr"), "fixture", platform)
			if e != ErrCode {
				t.Fatal(e)
			}
		})
	}
}
