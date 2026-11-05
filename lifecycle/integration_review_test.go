package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"eguard-nac-agent/journal"
)

// All envelopes use fresh in-memory Ed25519 keys, including deliberately poisoned
// journal entries. The mechanical journal does not itself authenticate records.
func TestReviewRecoverRejectsUnanchoredLifecycleAction(t *testing.T) {
	for _, action := range []string{"renew", "change_mode", "revoke"} {
		t.Run(action, func(t *testing.T) {
			h := newIntegrationHarness(t)
			mode := "permanent"
			if action == "change_mode" {
				mode = "temporary"
			}
			raw := h.grant(action, mode, "orphan", 1)
			if err := h.store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "orphan", Envelope: raw, AcceptedAt: epoch}); err != nil {
				t.Fatal(err)
			}
			h.reopen()
			if _, err := Recover(h.store, h.f.keys, expected); err == nil {
				t.Fatal("recovered transition without initial activate")
			}
		})
	}
}

func TestReviewRevokeTerminalAcrossReopen(t *testing.T) {
	h := newIntegrationHarness(t)
	h.accept(h.grant("activate", "permanent", "a", 1), epoch)
	h.accept(h.grant("revoke", "permanent", "v", 2), epoch)
	h.reopen()
	if o := h.recover(); o.State != "revoked" || o.CleanupPending {
		t.Fatal("revocation not terminal observation")
	}
	h.unchangedReject(h.grant("activate", "permanent", "reenable", 3), h.f.keys, expected, epoch)
}

func TestReviewPolicyMonotonicAndIdentityRequired(t *testing.T) {
	h := newIntegrationHarness(t)
	initialRaw := h.grant("activate", "permanent", "a", 1)
	var initial envelope
	if err := json.Unmarshal(initialRaw, &initial); err != nil {
		t.Fatal(err)
	}
	initialPayload, err := base64.StdEncoding.DecodeString(initial.Payload)
	if err != nil {
		t.Fatal(err)
	}
	initialPayload = bytes.Replace(initialPayload, []byte(`"policy_revision":1`), []byte(`"policy_revision":2`), 1)
	h.accept(h.f.wrap(initialPayload), epoch)
	p := bytes.Replace(h.grant("renew", "permanent", "r", 2), []byte(`"key_id":"test-key"`), []byte(`"key_id":"unknown"`), 1)
	h.unchangedReject(p, h.f.keys, expected, epoch)
	// Produce a fresh *signed* payload with lower policy revision, not a broken signature.
	raw := h.raw("renew", "permanent", "lower-policy", 2, integrationActivated, epoch, epoch+60)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	h.unchangedReject(h.f.wrap(decoded), h.f.keys, expected, epoch)
	for name, b := range map[string]Binding{"issuer": {DeviceID: expected.DeviceID, TenantID: expected.TenantID, SiteID: expected.SiteID, EnrollmentID: expected.EnrollmentID}, "device": {Issuer: expected.Issuer, TenantID: expected.TenantID, SiteID: expected.SiteID, EnrollmentID: expected.EnrollmentID}, "tenant": {Issuer: expected.Issuer, DeviceID: expected.DeviceID, SiteID: expected.SiteID, EnrollmentID: expected.EnrollmentID}, "site": {Issuer: expected.Issuer, DeviceID: expected.DeviceID, TenantID: expected.TenantID, EnrollmentID: expected.EnrollmentID}, "enrollment": {Issuer: expected.Issuer, DeviceID: expected.DeviceID, TenantID: expected.TenantID, SiteID: expected.SiteID}} {
		t.Run(name, func(t *testing.T) {
			h.unchangedReject(h.grant("renew", "permanent", "id-"+name, 2), h.f.keys, b, epoch)
		})
	}
}

func TestReviewUninstallAfterTemporaryExpiryCannotUseActiveObservation(t *testing.T) {
	h := newIntegrationHarness(t)
	activation := epoch - 3600
	// Session expires at activation+3600 == epoch. Grant authorization remains valid.
	raw := h.raw("activate", "temporary", "a", 1, activation, epoch-1, epoch+60)
	h.accept(raw, epoch-1)
	h.reopen()
	// Recover is historical and has no now: "active" is only a lifecycle label,
	// never a statement of present network access eligibility.
	if o := h.recover(); o.State != "active" {
		t.Fatal("historical lifecycle lost")
	}
	h.unchangedReject(h.raw("authorize_uninstall", "temporary", "i", 2, activation, epoch-1, epoch+60), h.f.keys, expected, epoch)
}

func TestReviewRecoverRejectsPoisonedAcceptanceTime(t *testing.T) {
	h := newIntegrationHarness(t)
	raw := h.raw("activate", "permanent", "a", 1, integrationActivated, epoch, epoch+60)
	if err := h.store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "a", Envelope: raw, AcceptedAt: epoch - 1}); err != nil {
		t.Fatal(err)
	}
	h.reopen()
	if _, err := Recover(h.store, h.f.keys, expected); err == nil {
		t.Fatal("recovered grant before issuance")
	}
}

func TestReviewCallerBufferAndTrustMapMutationAfterCommit(t *testing.T) {
	h := newIntegrationHarness(t)
	raw := h.grant("activate", "permanent", "a", 1)
	keyCopy := append(ed25519.PublicKey(nil), h.f.public...)
	keys := map[string]ed25519.PublicKey{"test-key": keyCopy}
	if _, err := Accept(h.store, raw, keys, expected, epoch); err != nil {
		t.Fatal(err)
	}
	snap, err := h.store.Read()
	if err != nil {
		t.Fatal(err)
	}
	saved := append([]byte(nil), snap.Lifecycle.Envelope...)
	for i := range raw {
		raw[i] = 0
	}
	if snap, err = h.store.Read(); err != nil || !bytes.Equal(snap.Lifecycle.Envelope, saved) {
		t.Fatal("journal aliased caller's envelope")
	}
	for i := range keyCopy {
		keyCopy[i] = 0
	}
	if _, err := Recover(h.store, keys, expected); err == nil {
		t.Fatal("recovery ignored mutated trust key")
	}
	h.reopen()
	if o, err := Recover(h.store, h.f.keys, expected); err != nil || o.State != "active" {
		t.Fatal("caller mutation damaged persisted envelope")
	}
}

func TestReviewTamperedAcceptanceTimeAndMixedSigner(t *testing.T) {
	h := newIntegrationHarness(t)
	h.accept(h.grant("activate", "permanent", "a", 1), epoch)
	h.reopen()
	otherPub, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := h.grant("renew", "permanent", "rotated", 2)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	p, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(otherPriv, append([]byte(prefix), p...))
	rotated := []byte(fmt.Sprintf(`{"version":1,"key_id":"rotated","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
	keys := map[string]ed25519.PublicKey{"test-key": h.f.public, "rotated": otherPub}
	if _, err := Accept(h.store, rotated, keys, expected, epoch); err != nil {
		t.Fatal(err)
	}
	h.reopen()
	if o, err := Recover(h.store, keys, expected); err != nil || o.LifecycleRevision != 2 {
		t.Fatal("mixed authorized signers did not recover")
	}
	// v3 verifies the entire history: the activation signer must remain trusted.
	if _, err := Recover(h.store, map[string]ed25519.PublicKey{"rotated": otherPub}, expected); err == nil {
		t.Fatal("history recovered without trusted activation signer")
	}
}
