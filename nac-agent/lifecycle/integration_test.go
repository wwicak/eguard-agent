package lifecycle

// Proposed production API (NOT implemented here):
//   Accept(store *journal.Store, rawEnvelope []byte, trustKeys map[string]ed25519.PublicKey,
//          binding Binding, trustedNow int64) (Observation, error)
//   Recover(store *journal.Store, trustKeys map[string]ed25519.PublicKey,
//           binding Binding) (Observation, error)
// Observation has State ("active", "revoked", "cleanup_pending", "cleanup_done"),
// Mode, ActivatedAt, LifecycleRevision, CleanupPending and IntentID fields.
// Accept requires an explicitly supplied trusted clock; it verifies signed bytes,
// the current state and acceptance window before atomically committing. Recover
// validates signed historical journal records and their committed acceptance times;
// it does NOT reaccept grants, use a local clock, or perform OS cleanup.

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"eguard-nac-agent/journal"
)

const integrationActivated int64 = epoch - 10

type integrationHarness struct {
	t     *testing.T
	f     fixture
	path  string
	store *journal.Store
}

func integrationBinding() journal.Binding {
	return journal.Binding{Device: expected.DeviceID, Tenant: expected.TenantID, Site: expected.SiteID, Enrollment: expected.EnrollmentID}
}
func newIntegrationHarness(t *testing.T) *integrationHarness {
	t.Helper()
	h := &integrationHarness{t: t, f: newFixture(t), path: filepath.Join(t.TempDir(), "state.db")}
	var err error
	h.store, err = journal.Create(h.path, integrationBinding())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if h.store != nil {
			if err := h.store.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return h
}
func (h *integrationHarness) reopen() {
	h.t.Helper()
	if err := h.store.Close(); err != nil {
		h.t.Fatal(err)
	}
	h.store = nil
	var err error
	h.store, err = journal.Open(h.path, integrationBinding())
	if err != nil {
		h.t.Fatal(err)
	}
}
func (h *integrationHarness) raw(action, mode, id string, rev uint64, activated, issued, until int64) []byte {
	h.t.Helper()
	expiry := "null"
	if mode == "temporary" {
		expiry = fmt.Sprint(activated + 3600)
	}
	p := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":"test-issuer","device_id":"device-1","tenant_id":"tenant-1","site_id":"site-1","enrollment_id":"enroll-1","grant_id":%q,"revision":%d,"policy_revision":1,"action":%q,"mode":%q,"issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":%s}`, id, rev, action, mode, issued, issued, until, activated, expiry))
	return h.f.wrap(p)
}
func (h *integrationHarness) grant(action, mode, id string, rev uint64) []byte {
	return h.raw(action, mode, id, rev, integrationActivated, epoch, epoch+60)
}
func (h *integrationHarness) accept(raw []byte, now int64) Observation {
	h.t.Helper()
	o, err := Accept(h.store, raw, h.f.keys, expected, now)
	if err != nil {
		h.t.Fatal(err)
	}
	return o
}
func (h *integrationHarness) recover() Observation {
	h.t.Helper()
	o, err := Recover(h.store, h.f.keys, expected)
	if err != nil {
		h.t.Fatal(err)
	}
	return o
}
func (h *integrationHarness) unchangedReject(raw []byte, keys map[string]ed25519.PublicKey, b Binding, now int64) {
	h.t.Helper()
	before, err := h.store.Read()
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err = Accept(h.store, raw, keys, b, now); err == nil {
		h.t.Fatal("invalid acceptance succeeded")
	}
	after, err := h.store.Read()
	if err != nil {
		h.t.Fatal(err)
	}
	if !equalIntegrationSnapshot(before, after) {
		h.t.Fatal("rejected grant changed journal")
	}
}
func equalIntegrationSnapshot(a, b journal.Snapshot) bool {
	if a.Version != b.Version || a.Binding != b.Binding || a.Revision != b.Revision || a.Lifecycle.Revision != b.Lifecycle.Revision || a.Lifecycle.AcceptedAt != b.Lifecycle.AcceptedAt || !bytes.Equal(a.Lifecycle.Envelope, b.Lifecycle.Envelope) || a.Cleanup.Revision != b.Cleanup.Revision || a.Cleanup.AcceptedAt != b.Cleanup.AcceptedAt || a.Cleanup.IntentID != b.Cleanup.IntentID || a.Cleanup.LifecycleRevision != b.Cleanup.LifecycleRevision || !bytes.Equal(a.Cleanup.Envelope, b.Cleanup.Envelope) || a.CleanupPending != b.CleanupPending || a.CleanupDone != b.CleanupDone || len(a.Nonces) != len(b.Nonces) {
		return false
	}
	for i := range a.Nonces {
		if a.Nonces[i] != b.Nonces[i] {
			return false
		}
	}
	return true
}

func TestIntegrationActivateRenewModeChangeAndDurableCAS(t *testing.T) {
	h := newIntegrationHarness(t)
	first := h.grant("activate", "permanent", "activate-1", 1)
	o := h.accept(first, epoch)
	if o.State != "active" || o.Mode != "permanent" || o.ActivatedAt != integrationActivated || o.LifecycleRevision != 1 {
		t.Fatal("wrong activation observation")
	}
	h.reopen()
	h.unchangedReject(first, h.f.keys, expected, epoch)
	// Increasing revision alone is insufficient to replay a consumed grant_id.
	h.unchangedReject(h.grant("renew", "permanent", "activate-1", 2), h.f.keys, expected, epoch)
	o = h.accept(h.grant("renew", "permanent", "renew-ok", 2), epoch)
	if o.State != "active" || o.LifecycleRevision != 2 || o.ActivatedAt != integrationActivated {
		t.Fatal("renew was not durable")
	}
	h.reopen()
	h.unchangedReject(h.grant("renew", "permanent", "renew-ok", 3), h.f.keys, expected, epoch)
}

func TestIntegrationConcurrentCASOnlyOneAccepted(t *testing.T) {
	h := newIntegrationHarness(t)
	h.accept(h.grant("activate", "permanent", "a", 1), epoch)
	raws := [][]byte{h.grant("renew", "permanent", "r-left", 2), h.grant("renew", "permanent", "r-right", 2)}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, raw := range raws {
		wg.Add(1)
		go func(raw []byte) {
			defer wg.Done()
			_, err := Accept(h.store, raw, h.f.keys, expected, epoch)
			results <- err
		}(raw)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent CAS successes=%d, want 1", successes)
	}
	h.reopen()
	snap, err := h.store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 2 || len(snap.Nonces) != 2 || h.recover().LifecycleRevision != 2 {
		t.Fatal("concurrent acceptance not durable")
	}
}

func TestIntegrationTransitionsAndTerminalRevoke(t *testing.T) {
	h := newIntegrationHarness(t)
	h.accept(h.grant("activate", "permanent", "a", 1), epoch)
	h.unchangedReject(h.raw("renew", "permanent", "reset", 2, integrationActivated+1, epoch, epoch+60), h.f.keys, expected, epoch)
	h.unchangedReject(h.grant("renew", "temporary", "implicit-mode", 2), h.f.keys, expected, epoch)
	o := h.accept(h.grant("renew", "permanent", "r", 2), epoch)
	if o.State != "active" || o.Mode != "permanent" || o.ActivatedAt != integrationActivated || o.LifecycleRevision != 2 {
		t.Fatal("renew changed activation or mode")
	}
	h.unchangedReject(h.grant("activate", "permanent", "duplicate-activate", 3), h.f.keys, expected, epoch)
	o = h.accept(h.grant("change_mode", "temporary", "m", 3), epoch)
	if o.State != "active" || o.Mode != "temporary" || o.ActivatedAt != integrationActivated || o.LifecycleRevision != 3 {
		t.Fatal("explicit mode change not recorded")
	}
	o = h.accept(h.grant("revoke", "temporary", "v", 4), epoch)
	if o.State != "revoked" || o.CleanupPending || o.IntentID != "" {
		t.Fatal("revoke incorrectly authorized uninstall")
	}
	h.reopen()
	if h.recover().State != "revoked" {
		t.Fatal("revoke not durable")
	}
	for _, action := range []string{"activate", "renew", "change_mode", "authorize_uninstall"} {
		t.Run(action, func(t *testing.T) {
			h.unchangedReject(h.grant(action, "temporary", "after-revoke-"+action, 5), h.f.keys, expected, epoch)
		})
	}
}

func TestIntegrationInvalidInputsLeaveDiskUnchanged(t *testing.T) {
	h := newIntegrationHarness(t)
	h.accept(h.grant("activate", "permanent", "a", 1), epoch)
	valid := h.grant("renew", "permanent", "r", 2)
	corrupted := append([]byte(nil), valid...)
	corrupted[len(corrupted)-3] ^= 1
	wrong := expected
	wrong.SiteID = "different-site"
	for name, tc := range map[string]struct {
		raw  []byte
		keys map[string]ed25519.PublicKey
		b    Binding
		now  int64
	}{
		"signature":        {corrupted, h.f.keys, expected, epoch},
		"trust key":        {valid, map[string]ed25519.PublicKey{"test-key": make(ed25519.PublicKey, ed25519.PublicKeySize)}, expected, epoch},
		"binding":          {valid, h.f.keys, wrong, epoch},
		"no trusted clock": {valid, h.f.keys, expected, 0},
		"future issuance":  {valid, h.f.keys, expected, epoch - 1},
		"expired":          {valid, h.f.keys, expected, epoch + 60},
		"stale revision":   {h.grant("renew", "permanent", "stale", 1), h.f.keys, expected, epoch},
	} {
		t.Run(name, func(t *testing.T) { h.unchangedReject(tc.raw, tc.keys, tc.b, tc.now); h.reopen() })
	}
}

func TestIntegrationUninstallRequiresActiveLifecycle(t *testing.T) {
	h := newIntegrationHarness(t)
	h.unchangedReject(h.grant("authorize_uninstall", "permanent", "premature", 1), h.f.keys, expected, epoch)
	h.accept(h.grant("activate", "permanent", "a", 1), epoch)
	h.accept(h.grant("revoke", "permanent", "v", 2), epoch)
	h.unchangedReject(h.grant("authorize_uninstall", "permanent", "after-revoke", 3), h.f.keys, expected, epoch)
}

func TestIntegrationUninstallDurablePendingAndHistoricalRecovery(t *testing.T) {
	h := newIntegrationHarness(t)
	lifecycleRaw := h.grant("activate", "permanent", "a", 1)
	h.accept(lifecycleRaw, epoch)
	expiredUnaccepted := h.raw("authorize_uninstall", "permanent", "expired", 2, integrationActivated, epoch, epoch+30)
	h.unchangedReject(expiredUnaccepted, h.f.keys, expected, epoch+30)
	h.unchangedReject(h.raw("authorize_uninstall", "permanent", "long-lived", 2, integrationActivated, epoch, epoch+601), h.f.keys, expected, epoch+1)
	h.unchangedReject(h.raw("authorize_uninstall", "temporary", "wrong-mode", 2, integrationActivated, epoch, epoch+60), h.f.keys, expected, epoch+1)
	uninstall := h.raw("authorize_uninstall", "permanent", "intent-1", 2, integrationActivated, epoch, epoch+600)
	o := h.accept(uninstall, epoch+1)
	if o.State != "cleanup_pending" || !o.CleanupPending || o.IntentID != "intent-1" || o.LifecycleRevision != 1 {
		t.Fatal("uninstall intent not associated with active lifecycle")
	}
	snap, err := h.store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snap.Lifecycle.Envelope, lifecycleRaw) || !bytes.Equal(snap.Cleanup.Envelope, uninstall) || snap.Cleanup.AcceptedAt != epoch+1 || snap.Cleanup.LifecycleRevision != 1 || snap.Revision != 2 {
		t.Fatal("signed envelopes/association not preserved")
	}
	h.reopen() // simulate boot after grant expiry: Recover has no clock and must not reaccept.
	o = h.recover()
	if o.State != "cleanup_pending" || !o.CleanupPending || o.IntentID != "intent-1" {
		t.Fatal("committed intent lost after boot")
	}
	h.unchangedReject(uninstall, h.f.keys, expected, epoch+1)
	if err := h.store.MarkCleanupDone("intent-1", expected.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	h.reopen()
	o = h.recover()
	if o.State != "cleanup_done" || o.CleanupPending {
		t.Fatal("completed intent resurrected after boot")
	}
}
func TestIntegrationPermanentHistoricalExpiryWithoutCleanup(t *testing.T) {
	h := newIntegrationHarness(t)
	h.accept(h.raw("activate", "permanent", "a", 1, integrationActivated, epoch, epoch+1), epoch)
	h.reopen()
	o := h.recover()
	if o.State != "active" || o.Mode != "permanent" || o.CleanupPending {
		t.Fatal("expired authorization incorrectly disabled permanent session")
	}
}

func TestIntegrationRecoverRejectsWrongBinding(t *testing.T) {
	h := newIntegrationHarness(t)
	h.accept(h.grant("activate", "permanent", "a", 1), epoch)
	h.reopen()
	wrong := expected
	wrong.SiteID = "other-site"
	if _, err := Recover(h.store, h.f.keys, wrong); err == nil {
		t.Fatal("recovery accepted a different installation binding")
	}
	if o := h.recover(); o.State != "active" {
		t.Fatal("failed recovery modified journal")
	}
}

func TestIntegrationRecoverRejectsUnverifiedOrInconsistentStoredRecords(t *testing.T) {
	for name, poison := range map[string]func(*integrationHarness){
		"wrong lifecycle signature": func(h *integrationHarness) {
			raw := h.grant("activate", "permanent", "a", 1)
			raw = append([]byte(nil), raw...)
			raw[len(raw)-3] ^= 1
			if err := h.store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "a", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"wrong lifecycle revision": func(h *integrationHarness) {
			raw := h.grant("activate", "permanent", "a", 2)
			if err := h.store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "a", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"wrong lifecycle action": func(h *integrationHarness) {
			raw := h.grant("authorize_uninstall", "permanent", "a", 1)
			if err := h.store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "a", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"wrong signed binding": func(h *integrationHarness) {
			p := payload("activate", "permanent", epoch, epoch, epoch+60)
			p = bytes.Replace(p, []byte(`"site_id":"site-1"`), []byte(`"site_id":"other-site"`), 1)
			raw := h.f.wrap(p)
			if err := h.store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "a", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"not accepted in window": func(h *integrationHarness) {
			raw := h.grant("activate", "permanent", "a", 1)
			if err := h.store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: 0, Revision: 1, Nonce: "a", Envelope: raw, AcceptedAt: epoch + 60}); err != nil {
				h.t.Fatal(err)
			}
		},
		"wrong cleanup signature": func(h *integrationHarness) {
			h.accept(h.grant("activate", "permanent", "a", 1), epoch)
			raw := h.grant("authorize_uninstall", "permanent", "i", 2)
			raw = append([]byte(nil), raw...)
			raw[len(raw)-3] ^= 1
			if err := h.store.AcceptCleanup(journal.CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 1, Nonce: "i", IntentID: "i", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"wrong cleanup action": func(h *integrationHarness) {
			h.accept(h.grant("activate", "permanent", "a", 1), epoch)
			raw := h.grant("renew", "permanent", "i", 2)
			if err := h.store.AcceptCleanup(journal.CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 1, Nonce: "i", IntentID: "i", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"wrong pending association": func(h *integrationHarness) {
			h.accept(h.grant("activate", "permanent", "a", 1), epoch)
			raw := h.grant("authorize_uninstall", "permanent", "different-id", 2)
			if err := h.store.AcceptCleanup(journal.CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 1, Nonce: "different-id", IntentID: "other-id", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"wrong cleanup signed binding": func(h *integrationHarness) {
			h.accept(h.grant("activate", "permanent", "a", 1), epoch)
			p := payload("authorize_uninstall", "permanent", epoch, epoch, epoch+60)
			p = bytes.Replace(p, []byte(`"site_id":"site-1"`), []byte(`"site_id":"other-site"`), 1)
			p = bytes.Replace(p, []byte(`"revision":1`), []byte(`"revision":2`), 1)
			raw := h.f.wrap(p)
			if err := h.store.AcceptCleanup(journal.CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 1, Nonce: "i", IntentID: "grant-1", Envelope: raw, AcceptedAt: epoch}); err != nil {
				h.t.Fatal(err)
			}
		},
		"unaccepted cleanup time": func(h *integrationHarness) {
			h.accept(h.grant("activate", "permanent", "a", 1), epoch)
			raw := h.grant("authorize_uninstall", "permanent", "i", 2)
			if err := h.store.AcceptCleanup(journal.CleanupTransition{ExpectedRevision: 1, Revision: 2, LifecycleRevision: 1, Nonce: "i", IntentID: "i", Envelope: raw, AcceptedAt: epoch + 60}); err != nil {
				h.t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newIntegrationHarness(t)
			poison(h)
			h.reopen()
			if _, err := Recover(h.store, h.f.keys, expected); err == nil {
				t.Fatal("inconsistent persisted record recovered")
			}
		})
	}
}
