package lifecycle

// Acceptance contract tests ONLY. The production package must provide:
// type Binding struct { Issuer, DeviceID, TenantID, SiteID, EnrollmentID string }
// type Grant struct { Purpose, Action, Mode string; IssuedAt, NotBefore, ValidUntil int64; Payload []byte }
// func VerifyEnvelope(raw []byte, keys map[string]ed25519.PublicKey, binding Binding) (Grant, error)
// func ValidateAcceptance(grant Grant, trustedNow int64) error
// Contract size ceilings: envelope <=256 KiB, decoded payload <=64 KiB.
// Caller supplies trustedNow in UTC epoch seconds; this API cannot establish clock trust.
// VerifyEnvelope validates signed historical bytes/schema/binding, WITHOUT checking
// today's acceptance window. ValidateAcceptance checks time on a verified grant;
// neither function mutates a journal, trusts a local clock, or authorizes cleanup.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const prefix = "eguard-nac-lifecycle/v1\x00"
const epoch int64 = 1700000000

var expected = Binding{Issuer: "test-issuer", DeviceID: "device-1", TenantID: "tenant-1", SiteID: "site-1", EnrollmentID: "enroll-1"}

type fixture struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	keys    map[string]ed25519.PublicKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	return fixture{pub, priv, map[string]ed25519.PublicKey{"test-key": pub}}
}

// Only ephemeral test keys are generated; no private key or signed secret is logged.
func (f fixture) wrap(payload []byte) []byte {
	sig := ed25519.Sign(f.private, append([]byte(prefix), payload...))
	return []byte(fmt.Sprintf(`{"version":1,"key_id":"test-key","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(sig)))
}
func payload(action, mode string, issued, notBefore, until int64) []byte {
	expiry := "null"
	if mode == "temporary" {
		expiry = fmt.Sprint(epoch + 3600)
	}
	return []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":"test-issuer","device_id":"device-1","tenant_id":"tenant-1","site_id":"site-1","grant_id":"grant-1","revision":1,"action":%q,"issued_at":%d,"not_before":%d,"valid_until":%d,"mode":%q,"activated_at":%d,"session_expires_at":%s,"policy_revision":1,"enrollment_id":"enroll-1"}`, action, issued, notBefore, until, mode, epoch-10, expiry))
}
func signed(t *testing.T, f fixture, p []byte) Grant {
	t.Helper()
	g, e := VerifyEnvelope(f.wrap(p), f.keys, expected)
	if e != nil {
		t.Fatalf("expected signed fixture accepted: %v", e)
	}
	return g
}
func denied(t *testing.T, raw []byte, f fixture, b Binding) {
	t.Helper()
	if _, e := VerifyEnvelope(raw, f.keys, b); e == nil {
		t.Fatal("invalid envelope accepted")
	}
}

func TestVerifyEnvelopeHistoricalPermanentRetainsRawSignedBytesAfterExpiry(t *testing.T) {
	f := newFixture(t)
	original := payload("activate", "permanent", epoch, epoch, epoch+60)
	// Whitespace is inside the signed bytes, not a canonicalized JSON representation.
	original = bytes.Replace(original, []byte(`"purpose":`), []byte(`"purpose" : `), 1)
	g := signed(t, f, original)
	if !bytes.Equal(g.Payload, original) || g.Mode != "permanent" || g.Action != "activate" || g.Purpose != "eguard-nac-lifecycle" {
		t.Fatal("decoded grant lost signed bytes or fields")
	}
	if e := ValidateAcceptance(g, epoch+60); e == nil {
		t.Fatal("expiry boundary accepted")
	}
	// Historical verification must still succeed after expiry; this does NOT authorize
	// a new acceptance, infer a committed journal record, or trigger auto-uninstall.
	if _, e := VerifyEnvelope(f.wrap(original), f.keys, expected); e != nil {
		t.Fatal("expired permanent cannot be reverified", e)
	}
}
func TestVerifyEnvelopeRejectsReserializationAndMutatedSignedPayload(t *testing.T) {
	f := newFixture(t)
	p := payload("activate", "permanent", epoch, epoch, epoch+60)
	original := f.wrap(p)
	var m map[string]any
	if e := json.Unmarshal(original, &m); e != nil {
		t.Fatal(e)
	}
	// Preserve the genuine signature but alter just the raw signed JSON whitespace.
	m["payload_b64"] = base64.StdEncoding.EncodeToString(bytes.Replace(p, []byte(`"purpose":`), []byte(`"purpose" : `), 1))
	bad, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	denied(t, bad, f, expected)
	sig, err := base64.StdEncoding.DecodeString(m["signature_b64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	m["signature_b64"] = base64.StdEncoding.EncodeToString(sig)
	altered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	denied(t, altered, f, expected)
}
func TestVerifyEnvelopeStrictOuterSchema(t *testing.T) {
	f := newFixture(t)
	p := payload("activate", "permanent", epoch, epoch, epoch+60)
	valid := f.wrap(p)
	cases := map[string][]byte{
		"duplicate version":        bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"unknown field":            bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"extra":1`), 1),
		"unsupported version":      bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":2`), 1),
		"wrong key id":             bytes.Replace(valid, []byte(`"test-key"`), []byte(`"untrusted"`), 1),
		"missing key id":           bytes.Replace(valid, []byte(`"key_id":"test-key",`), nil, 1),
		"invalid payload base64":   bytes.Replace(valid, []byte(`"payload_b64":"`), []byte(`"payload_b64":"!`), 1),
		"invalid signature base64": bytes.Replace(valid, []byte(`"signature_b64":"`), []byte(`"signature_b64":"!`), 1),
		"trailing JSON":            append(append([]byte(nil), valid...), []byte(` {}`)...),
		"oversized envelope":       []byte(strings.Repeat("x", 1024*1024)),
		"oversized signed payload": f.wrap([]byte(strings.Repeat("x", 1024*1024))),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) { denied(t, raw, f, expected) })
	}
}
func TestVerifyEnvelopeRejectsSignedPayloadSchemaAndBinding(t *testing.T) {
	f := newFixture(t)
	p := payload("activate", "permanent", epoch, epoch, epoch+60)
	cases := map[string][]byte{
		"duplicate payload key":    bytes.Replace(p, []byte(`"issuer":"test-issuer"`), []byte(`"issuer":"test-issuer","issuer":"test-issuer"`), 1),
		"unknown payload field":    bytes.Replace(p, []byte(`"issuer":"test-issuer"`), []byte(`"issuer":"test-issuer","extra":1`), 1),
		"wrong purpose":            bytes.Replace(p, []byte(`"purpose":"eguard-nac-lifecycle"`), []byte(`"purpose":"other-protocol"`), 1),
		"wrong protocol":           bytes.Replace(p, []byte(`"protocol_version":1`), []byte(`"protocol_version":2`), 1),
		"wrong action":             bytes.Replace(p, []byte(`"action":"activate"`), []byte(`"action":"run_command"`), 1),
		"wrong issuer":             bytes.Replace(p, []byte(`"issuer":"test-issuer"`), []byte(`"issuer":"other"`), 1),
		"wrong device":             bytes.Replace(p, []byte(`"device_id":"device-1"`), []byte(`"device_id":"device-2"`), 1),
		"wrong tenant":             bytes.Replace(p, []byte(`"tenant_id":"tenant-1"`), []byte(`"tenant_id":"tenant-2"`), 1),
		"wrong site":               bytes.Replace(p, []byte(`"site_id":"site-1"`), []byte(`"site_id":"site-2"`), 1),
		"wrong enrollment":         bytes.Replace(p, []byte(`"enrollment_id":"enroll-1"`), []byte(`"enrollment_id":"enroll-2"`), 1),
		"missing policy revision":  bytes.Replace(p, []byte(`,"policy_revision":1`), nil, 1),
		"invalid permanent expiry": bytes.Replace(p, []byte(`"session_expires_at":null`), []byte(`"session_expires_at":123`), 1),
		"trailing signed payload":  append(append([]byte(nil), p...), []byte(` {}`)...),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) { denied(t, f.wrap(b), f, expected) })
	}
	for name, change := range map[string]func(*Binding){"expected issuer": func(b *Binding) { b.Issuer = "other" }, "expected device": func(b *Binding) { b.DeviceID = "other" }, "expected tenant": func(b *Binding) { b.TenantID = "other" }, "expected site": func(b *Binding) { b.SiteID = "other" }, "expected enrollment": func(b *Binding) { b.EnrollmentID = "other" }} {
		t.Run(name, func(t *testing.T) { b := expected; change(&b); denied(t, f.wrap(p), f, b) })
	}
}
func TestValidateAcceptanceWindowAndUninstallIssuanceCap(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, action                  string
		issued, notBefore, until, now int64
		accept                        bool
	}{
		{"not before inclusive", "activate", epoch, epoch + 10, epoch + 60, epoch + 10, true},
		{"before not before", "activate", epoch, epoch + 10, epoch + 60, epoch + 9, false},
		{"before expiry", "activate", epoch, epoch, epoch + 60, epoch + 59, true},
		{"expiry exclusive", "activate", epoch, epoch, epoch + 60, epoch + 60, false},
		{"future issued at", "activate", epoch + 1, epoch, epoch + 60, epoch, false},
		{"uninstall at 600 seconds", "authorize_uninstall", epoch, epoch, epoch + 600, epoch + 599, true},
		{"uninstall validity exceeds 600 since issuance", "authorize_uninstall", epoch, epoch + 590, epoch + 601, epoch + 590, false},
		{"uninstall stale issuance even if deadline near now", "authorize_uninstall", epoch - 10000, epoch - 10000, epoch + 1, epoch, false},
		{"uninstall expires exactly now", "authorize_uninstall", epoch, epoch, epoch + 600, epoch + 600, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := signed(t, f, payload(tc.action, "permanent", tc.issued, tc.notBefore, tc.until))
			e := ValidateAcceptance(g, tc.now)
			if (e == nil) != tc.accept {
				t.Fatalf("accept=%v want=%v", e == nil, tc.accept)
			}
		})
	}
}
