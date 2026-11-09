package uninstall

import (
	"encoding/base64"
	"strings"
	"testing"
)

// An authorization can be pasted as one text token (base64url of the signed
// envelope) — e.g. read out by the helpdesk to a guest who has left the network.
func TestTokenRoundTrip(t *testing.T) {
	env := []byte(`{"version":1,"key_id":"k1","payload_b64":"eA==","signature_b64":"eQ=="}`)
	tok := EncodeToken(env)
	if strings.ContainsAny(tok, "+/= \n") {
		t.Fatalf("token not url-safe: %q", tok)
	}
	got, e := DecodeToken("  " + tok + "\r\n")
	if e != nil || string(got) != string(env) {
		t.Fatalf("got=%q e=%v", got, e)
	}
}

func TestTokenRejectsGarbageAndOversize(t *testing.T) {
	for _, bad := range []string{"", "!!!", base64.RawURLEncoding.EncodeToString([]byte("not json")), strings.Repeat("A", 200000)} {
		if _, e := DecodeToken(bad); e == nil {
			t.Errorf("accepted %.20q", bad)
		}
	}
}
