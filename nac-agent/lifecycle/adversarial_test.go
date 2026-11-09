package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math"
	"testing"
)

// All signatures in this file use newFixture's ephemeral private key; never log it.
func TestAdversarialForgedGrantAndExportedMutation(t *testing.T) {
	f := newFixture(t)
	if ValidateAcceptance(Grant{Purpose: "eguard-nac-lifecycle", Action: "activate", Mode: "permanent", IssuedAt: epoch, NotBefore: epoch, ValidUntil: epoch + 60, Payload: payload("activate", "permanent", epoch, epoch, epoch+60)}, epoch) == nil {
		t.Fatal("unverified grant admitted")
	}
	g := signed(t, f, payload("activate", "permanent", epoch, epoch, epoch+60))
	g.Action = "authorize_uninstall"
	g.Mode = "temporary"
	g.IssuedAt = 1
	g.NotBefore = 1
	g.ValidUntil = math.MaxInt64
	g.Purpose = "other"
	g.Payload = payload("authorize_uninstall", "temporary", 1, 1, math.MaxInt64)
	// Callers can dispatch using exported Action/Mode/Payload after this check.
	// Acceptance must not return success for a grant whose visible fields contradict
	// the verified statement, even though the internal time window stays intact.
	if ValidateAcceptance(g, epoch) == nil {
		t.Fatal("mutated exported grant accepted despite conflicting dispatch fields")
	}
	u := signed(t, f, payload("authorize_uninstall", "permanent", epoch, epoch, epoch+601))
	u.Action = "activate"
	u.ValidUntil = math.MaxInt64
	if ValidateAcceptance(u, epoch) == nil {
		t.Fatal("exported mutation bypassed uninstall duration")
	}
}
func TestAdversarialKeyLengthsAndPurposeSeparation(t *testing.T) {
	f := newFixture(t)
	p := payload("activate", "permanent", epoch, epoch, epoch+60)
	raw := f.wrap(p)
	for _, tc := range []struct {
		name string
		key  ed25519.PublicKey
	}{{"empty", nil}, {"short", ed25519.PublicKey{1}}, {"long", make(ed25519.PublicKey, ed25519.PublicKeySize+1)}} {
		t.Run(tc.name, func(t *testing.T) {
			keys := map[string]ed25519.PublicKey{"test-key": tc.key}
			if _, e := VerifyEnvelope(raw, keys, expected); e == nil {
				t.Fatal("bad trust key accepted")
			}
		})
	}
	// A valid signature under a different protocol prefix is not a lifecycle signature.
	sig := ed25519.Sign(f.private, append([]byte("other-purpose/v1\x00"), p...))
	wrong := []byte(fmt.Sprintf(`{"version":1,"key_id":"test-key","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
	denied(t, wrong, f, expected)
}
func TestAdversarialRequiredNullCaseAndAliases(t *testing.T) {
	f := newFixture(t)
	p := payload("activate", "permanent", epoch, epoch, epoch+60)
	replace := func(old, new string) []byte {
		t.Helper()
		if !bytes.Contains(p, []byte(old)) {
			t.Fatalf("fixture missing %s", old)
		}
		return bytes.Replace(p, []byte(old), []byte(new), 1)
	}
	cases := map[string][]byte{
		"missing signed action":              replace(`,"action":"activate"`, ``),
		"null signed action":                 replace(`"action":"activate"`, `"action":null`),
		"null signed revision":               replace(`"revision":1`, `"revision":null`),
		"wrong case key":                     replace(`"action":`, `"Action":`),
		"alias key":                          replace(`"device_id":`, `"deviceId":`),
		"duplicate case alias":               replace(`"action":`, `"action":"activate","Action":`),
		"escaped invalid unicode identifier": replace(`"grant_id":"grant-1"`, `"grant_id":"\ud800"`),
		"escaped invalid unicode key":        replace(`"grant_id":`, `"grant_\ud800id":`),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) { denied(t, f.wrap(p), f, expected) })
	}
	outer := f.wrap(p)
	for name, v := range map[string]string{"null envelope key": `"key_id":null`, "wrong envelope case": `"Key_id":"test-key"`, "escaped invalid unicode envelope key": `"key_\ud800id":"test-key"`} {
		t.Run(name, func(t *testing.T) {
			denied(t, bytes.Replace(outer, []byte(`"key_id":"test-key"`), []byte(v), 1), f, expected)
		})
	}
}
func TestAdversarialTimestampBoundaries(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, action           string
		issued, nb, until, now int64
		accept                 bool
	}{
		{"max int64 valid interval", "activate", math.MaxInt64 - 2, math.MaxInt64 - 2, math.MaxInt64, math.MaxInt64 - 1, true},
		{"max int64 exclusive end", "activate", math.MaxInt64 - 2, math.MaxInt64 - 2, math.MaxInt64, math.MaxInt64, false},
		{"uninstall max duration", "authorize_uninstall", math.MaxInt64 - 600, math.MaxInt64 - 600, math.MaxInt64, math.MaxInt64 - 1, true},
		{"uninstall 601 duration", "authorize_uninstall", math.MaxInt64 - 601, math.MaxInt64 - 601, math.MaxInt64, math.MaxInt64 - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := signed(t, f, payload(tc.action, "permanent", tc.issued, tc.nb, tc.until))
			if got := ValidateAcceptance(g, tc.now) == nil; got != tc.accept {
				t.Fatalf("accept=%v want=%v", got, tc.accept)
			}
		})
	}
	for name, p := range map[string][]byte{
		"zero issued":     payload("activate", "permanent", 0, 1, 2),
		"negative issued": payload("activate", "permanent", math.MinInt64, 1, 2),
		"inverted window": payload("activate", "permanent", epoch, epoch+2, epoch+1),
	} {
		t.Run(name, func(t *testing.T) { denied(t, f.wrap(p), f, expected) })
	}
}
func TestAdversarialTemporaryExpiryAndLifecycleTimestampContradiction(t *testing.T) {
	f := newFixture(t)
	p := payload("activate", "temporary", epoch, epoch, epoch+60)
	for name, fromTo := range map[string][2]string{
		"missing temporary expiry": {`"session_expires_at":1700003600`, ``},
		"null temporary expiry":    {`"session_expires_at":1700003600`, `"session_expires_at":null`},
		"expiry equals activation": {`"session_expires_at":1700003600`, `"session_expires_at":1699999990`},
	} {
		t.Run(name, func(t *testing.T) {
			changed := bytes.Replace(p, []byte(fromTo[0]), []byte(fromTo[1]), 1)
			if bytes.Equal(changed, p) {
				t.Fatal("fixture substitution failed")
			}
			denied(t, f.wrap(changed), f, expected)
		})
	}
	g := signed(t, f, p)
	if ValidateAcceptance(g, epoch) != nil {
		t.Fatal("valid temporary authorization rejected")
	}
	if ValidateAcceptance(g, epoch+60) == nil {
		t.Fatal("authorization window expiry admitted")
	}
	// Session expiry is distinct from grant-window expiry: no cleanup permission is inferred here.
}
