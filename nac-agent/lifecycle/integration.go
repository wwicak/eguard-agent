package lifecycle

import (
	"crypto/ed25519"
	"eguard-nac-agent/journal"
	"encoding/json"
)

// Observation is verified persisted state, never permission for an OS operation.
type Observation struct {
	State, Mode       string
	ActivatedAt       int64
	LifecycleRevision uint64
	CleanupPending    bool
	IntentID          string
}

func record(raw []byte, keys map[string]ed25519.PublicKey, b Binding, at int64) (statement, error) {
	var s statement
	g, e := VerifyEnvelope(raw, keys, b)
	if e != nil {
		return s, e
	}
	if e = ValidateAcceptance(g, at); e != nil {
		return s, e
	}
	e = json.Unmarshal([]byte(g.originalPayload), &s)
	return s, e
}
func bound(p journal.Snapshot, b Binding) bool {
	return p.Binding == (journal.Binding{Device: b.DeviceID, Tenant: b.TenantID, Site: b.SiteID, Enrollment: b.EnrollmentID})
}
func contains(ns []string, n string) bool {
	for _, x := range ns {
		if x == n {
			return true
		}
	}
	return false
}
func sameSession(a, b statement) bool {
	if a.Mode != b.Mode || a.Activated != b.Activated {
		return false
	}
	if a.Expires == nil || b.Expires == nil {
		return a.Expires == nil && b.Expires == nil
	}
	return *a.Expires == *b.Expires
}
func recoverSnapshot(p journal.Snapshot, keys map[string]ed25519.PublicKey, b Binding) (Observation, statement, error) {
	var o Observation
	var s statement
	if !bound(p, b) {
		return o, s, errInvalid
	}
	if p.Revision == 0 {
		o.State = "pending"
		return o, s, nil
	}
	if len(p.History) == 0 {
		return o, s, errInvalid
	}
	seen := map[string]bool{}
	var previousAt int64
	for i, h := range p.History {
		n, e := record(h.Envelope, keys, b, h.AcceptedAt)
		if e != nil {
			return o, s, e
		}
		if n.Revision != h.Revision || seen[n.ID] || !contains(p.Nonces, n.ID) || n.Activated > h.AcceptedAt {
			return o, s, errInvalid
		}
		if i == 0 {
			if n.Action != "activate" {
				return o, s, errInvalid
			}
		} else {
			if s.Action == "revoke" || n.Revision <= s.Revision || h.AcceptedAt < previousAt || n.Activated != s.Activated || n.PolicyRevision < s.PolicyRevision {
				return o, s, errInvalid
			}
			switch n.Action {
			case "renew":
				if n.Mode != s.Mode {
					return o, s, errInvalid
				}
			case "change_mode":
				if n.Mode == s.Mode {
					return o, s, errInvalid
				}
			case "revoke":
				if !sameSession(n, s) {
					return o, s, errInvalid
				}
			default:
				return o, s, errInvalid
			}
		}
		seen[n.ID] = true
		previousAt = h.AcceptedAt
		s = n
	}
	if s.Revision != p.Lifecycle.Revision {
		return o, s, errInvalid
	}
	o = Observation{State: "active", Mode: s.Mode, ActivatedAt: s.Activated, LifecycleRevision: s.Revision}
	if s.Action == "revoke" {
		o.State = "revoked"
	}
	if p.CleanupPending || p.CleanupDone {
		c, e := record(p.Cleanup.Envelope, keys, b, p.Cleanup.AcceptedAt)
		if e != nil {
			return Observation{}, s, e
		}
		if o.State != "active" || c.Action != "authorize_uninstall" || !sameSession(c, s) || c.PolicyRevision != s.PolicyRevision || c.Revision != p.Cleanup.Revision || c.Revision != p.Revision || c.Revision <= s.Revision || p.Cleanup.LifecycleRevision != s.Revision || c.ID != p.Cleanup.IntentID || !contains(p.Nonces, c.ID) || p.Cleanup.AcceptedAt < p.Lifecycle.AcceptedAt {
			return Observation{}, s, errInvalid
		}
		o.State = "cleanup_pending"
		o.CleanupPending = p.CleanupPending
		o.IntentID = c.ID
		if p.CleanupDone {
			o.State = "cleanup_done"
		}
	} else if p.Revision != s.Revision {
		return Observation{}, s, errInvalid
	}
	return o, s, nil
}

// Recover verifies historical admission at stored acceptance times. Disk state
// is not rollback-resistant or proof of clock trust; OS cleanup remains unwired.
func Recover(store *journal.Store, keys map[string]ed25519.PublicKey, b Binding) (Observation, error) {
	if store == nil {
		return Observation{}, errInvalid
	}
	p, e := store.Read()
	if e != nil {
		return Observation{}, e
	}
	o, _, e := recoverSnapshot(p, keys, b)
	return o, e
}
func Accept(store *journal.Store, raw []byte, keys map[string]ed25519.PublicKey, b Binding, now int64) (Observation, error) {
	if store == nil {
		return Observation{}, errInvalid
	}
	// Copy caller bytes before verification and persistence.
	raw = append([]byte(nil), raw...)
	n, e := record(raw, keys, b, now)
	if e != nil {
		return Observation{}, e
	}
	p, e := store.Read()
	if e != nil {
		return Observation{}, e
	}
	old, s, e := recoverSnapshot(p, keys, b)
	if e != nil {
		return Observation{}, e
	}
	if n.Revision <= p.Revision || n.Activated > now || old.State == "revoked" || old.State == "cleanup_pending" || old.State == "cleanup_done" {
		return Observation{}, errInvalid
	}
	if p.Revision == 0 {
		if n.Action != "activate" {
			return Observation{}, errInvalid
		}
	} else {
		if now < p.Lifecycle.AcceptedAt || n.Activated != s.Activated || n.PolicyRevision < s.PolicyRevision {
			return Observation{}, errInvalid
		}
		switch n.Action {
		case "renew":
			if n.Mode != s.Mode {
				return Observation{}, errInvalid
			}
		case "change_mode":
			if n.Mode == s.Mode {
				return Observation{}, errInvalid
			}
		case "revoke", "authorize_uninstall":
			if !sameSession(n, s) {
				return Observation{}, errInvalid
			}
		default:
			return Observation{}, errInvalid
		}
	}
	if n.Action == "authorize_uninstall" {
		// Explicit uninstall currently requires a live Temporary session.
		// Expiry cleanup is a separate future path, not this authorization.
		if n.PolicyRevision != s.PolicyRevision || (s.Mode == "temporary" && (s.Expires == nil || now >= *s.Expires)) {
			return Observation{}, errInvalid
		}
		e = store.AcceptCleanup(journal.CleanupTransition{ExpectedRevision: p.Revision, Revision: n.Revision, LifecycleRevision: s.Revision, Nonce: n.ID, IntentID: n.ID, Envelope: raw, AcceptedAt: now})
	} else {
		e = store.AcceptLifecycle(journal.LifecycleTransition{ExpectedRevision: p.Revision, Revision: n.Revision, Nonce: n.ID, Envelope: raw, AcceptedAt: now})
	}
	if e != nil {
		return Observation{}, e
	}
	return Recover(store, keys, b)
}
