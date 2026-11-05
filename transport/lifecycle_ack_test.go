package transport

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
)

// Remote uninstall: the server may attach ONE signed lifecycle envelope to the
// posture acknowledgement. Transport only decodes and hands it over; trust comes
// from the lifecycle signature checked by the caller, never from TLS alone.
func TestAcknowledgementCarriesOptionalLifecycle(t *testing.T) {
	env := []byte(`{"version":1,"key_id":"k","payload_b64":"e30=","signature_b64":"AA=="}`)
	cases := []struct {
		name, body string
		ok         bool
		want       []byte
	}{
		{"plain", `{"accepted":true}`, true, nil},
		{"with lifecycle", `{"accepted":true,"lifecycle":"` + base64.RawURLEncoding.EncodeToString(env) + `"}`, true, env},
		{"lifecycle not string", `{"accepted":true,"lifecycle":5}`, false, nil},
		{"lifecycle bad base64", `{"accepted":true,"lifecycle":"!!"}`, false, nil},
		{"lifecycle first", `{"lifecycle":"e30","accepted":true}`, false, nil},
		{"unknown field", `{"accepted":true,"other":"x"}`, false, nil},
		{"duplicate lifecycle", `{"accepted":true,"lifecycle":"e30","lifecycle":"e30"}`, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeCerts(t)
			srv := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(tc.body))
			})
			var got []byte
			calls := 0
			cfg := config(srv, f)
			cfg.OnLifecycle = func(b []byte) { calls++; got = b }
			c, e := NewClient(cfg)
			if e != nil {
				t.Fatal(e)
			}
			e = c.SendPosture(context.Background(), posture())
			if (e == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", e, tc.ok)
			}
			if tc.want == nil && calls != 0 || tc.want != nil && (calls != 1 || string(got) != string(tc.want)) {
				t.Fatalf("calls=%d got=%q", calls, got)
			}
		})
	}
}
