package selfenroll

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Guest-facing refusals must read as plain guidance, not raw HTTP codes.
func TestRedeemExplainsGuestRefusals(t *testing.T) {
	for status, want := range map[int]string{
		http.StatusConflict:        "guest device limit",
		http.StatusTooManyRequests: "too many enrollment attempts",
	} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		_, err := Redeem(srv.URL+"/v1/nac/enroll", pool, "K7Q2M-9XRTA", []byte("csr"), "host")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "HTTP") {
			t.Fatalf("%d: %v", status, err)
		}
		if errors.Is(err, ErrCode) {
			t.Fatalf("%d must not be reported as a bad code", status)
		}
	}
}
