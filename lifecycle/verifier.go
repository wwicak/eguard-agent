// Package lifecycle verifies signed statements, not permission to perform cleanup.
package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var errInvalid = errors.New("invalid lifecycle statement")

type Binding struct{ Issuer, DeviceID, TenantID, SiteID, EnrollmentID string }
type Grant struct {
	Purpose, Action, Mode           string
	IssuedAt, NotBefore, ValidUntil int64
	Payload                         []byte
	// Private verified fields prevent exported-field mutations from changing acceptance.
	verified                       bool
	action                         string
	purpose, mode, originalPayload string
	issued, notBefore, until       int64
}
type envelope struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload_b64"`
	Signature string `json:"signature_b64"`
}
type statement struct {
	Version        int    `json:"protocol_version"`
	Purpose        string `json:"purpose"`
	Issuer         string `json:"issuer"`
	Device         string `json:"device_id"`
	Tenant         string `json:"tenant_id"`
	Site           string `json:"site_id"`
	Enrollment     string `json:"enrollment_id"`
	ID             string `json:"grant_id"`
	Revision       uint64 `json:"revision"`
	PolicyRevision uint64 `json:"policy_revision"`
	Action         string `json:"action"`
	Mode           string `json:"mode"`
	Issued         int64  `json:"issued_at"`
	NotBefore      int64  `json:"not_before"`
	Until          int64  `json:"valid_until"`
	Activated      int64  `json:"activated_at"`
	Expires        *int64 `json:"session_expires_at"`
}

// flat strictly validates exact, required keys before typed decoding. Both schemas
// are flat; nested objects/arrays are never valid here.
func flat(raw []byte, keys []string, nullable string, out any) error {
	if !utf8.Valid(raw) {
		return errInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errInvalid
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	seen := map[string]bool{}
	for d.More() {
		t, e = d.Token()
		if e != nil {
			return errInvalid
		}
		k, ok := t.(string)
		if !ok || !allowed[k] || seen[k] {
			return errInvalid
		}
		seen[k] = true
		v, e := d.Token()
		if e != nil {
			return errInvalid
		}
		if _, ok := v.(json.Delim); ok {
			return errInvalid
		}
		if v == nil && k != nullable {
			return errInvalid
		}
	}
	if t, e = d.Token(); e != nil || t != json.Delim('}') || len(seen) != len(keys) {
		return errInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return errInvalid
	}
	if json.Unmarshal(raw, out) != nil {
		return errInvalid
	}
	return nil
}
func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
func decode64(s string, max int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(max) {
		return nil, errInvalid
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) > max || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errInvalid
	}
	return b, nil
}

// VerifyEnvelope has no clock or side effects. Trust keys and binding must come
// from authenticated provisioning, never from the envelope itself.
func VerifyEnvelope(raw []byte, keys map[string]ed25519.PublicKey, b Binding) (Grant, error) {
	var zero Grant
	if len(raw) == 0 || len(raw) > 256*1024 {
		return zero, errInvalid
	}
	for _, s := range []string{b.Issuer, b.DeviceID, b.TenantID, b.SiteID, b.EnrollmentID} {
		if !identifier(s) {
			return zero, errInvalid
		}
	}
	var env envelope
	if flat(raw, []string{"version", "key_id", "payload_b64", "signature_b64"}, "", &env) != nil || env.Version != 1 || !identifier(env.KeyID) {
		return zero, errInvalid
	}
	key := keys[env.KeyID]
	if len(key) != ed25519.PublicKeySize {
		return zero, errInvalid
	}
	p, e := decode64(env.Payload, 64*1024)
	if e != nil {
		return zero, e
	}
	sig, e := decode64(env.Signature, ed25519.SignatureSize)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return zero, errInvalid
	}
	message := append([]byte("eguard-nac-lifecycle/v1\x00"), p...)
	if !ed25519.Verify(key, message, sig) {
		return zero, errInvalid
	}
	var s statement
	fields := []string{"protocol_version", "purpose", "issuer", "device_id", "tenant_id", "site_id", "enrollment_id", "grant_id", "revision", "policy_revision", "action", "mode", "issued_at", "not_before", "valid_until", "activated_at", "session_expires_at"}
	if flat(p, fields, "session_expires_at", &s) != nil {
		return zero, errInvalid
	}
	if s.Version != 1 || s.Purpose != "eguard-nac-lifecycle" || s.Issuer != b.Issuer || s.Device != b.DeviceID || s.Tenant != b.TenantID || s.Site != b.SiteID || s.Enrollment != b.EnrollmentID || !identifier(s.ID) || s.Revision == 0 || s.PolicyRevision == 0 {
		return zero, errInvalid
	}
	switch s.Action {
	case "activate", "renew", "change_mode", "revoke", "authorize_uninstall":
	default:
		return zero, errInvalid
	}
	if s.Issued <= 0 || s.NotBefore <= 0 || s.Until <= s.Issued || s.Until <= s.NotBefore || s.Activated <= 0 {
		return zero, errInvalid
	}
	switch s.Mode {
	case "permanent":
		if s.Expires != nil {
			return zero, errInvalid
		}
	case "temporary":
		if s.Expires == nil || *s.Expires <= s.Activated {
			return zero, errInvalid
		}
	default:
		return zero, errInvalid
	}
	return Grant{Purpose: s.Purpose, Action: s.Action, Mode: s.Mode, IssuedAt: s.Issued, NotBefore: s.NotBefore, ValidUntil: s.Until, Payload: append([]byte(nil), p...), verified: true, action: s.Action, purpose: s.Purpose, mode: s.Mode, originalPayload: string(p), issued: s.Issued, notBefore: s.NotBefore, until: s.Until}, nil
}

// ValidateAcceptance checks only the admission time window of a verified grant.
// It does not establish clock trust, replay safety, transition validity or RBAC.
func ValidateAcceptance(g Grant, trustedNow int64) error {
	if !g.verified || g.Action != g.action || g.Purpose != g.purpose || g.Mode != g.mode || g.IssuedAt != g.issued || g.NotBefore != g.notBefore || g.ValidUntil != g.until || string(g.Payload) != g.originalPayload || trustedNow <= 0 || trustedNow < g.issued || trustedNow < g.notBefore || trustedNow >= g.until {
		return errInvalid
	}
	// Positive ordered int64 timestamps make this subtraction overflow-safe.
	if g.action == "authorize_uninstall" && g.until-g.issued > 600 {
		return errInvalid
	}
	return nil
}
