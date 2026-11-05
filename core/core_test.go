package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestPostureUnknownAndFreshness(t *testing.T) {
	p := Posture{Domain: DomainEvidence{PartOfDomain: Unknown, Match: Unknown}, AV: AVEvidence{Installed: Unknown, Running: Unknown, Updated: Unknown}, Firewall: map[string]Evidence{"public": {Value: Unknown}}, ObservedAt: time.Unix(100, 0), TTL: time.Minute}
	if p.Domain.Result() != Unknown || p.AV.Result() != Unknown || p.Firewall["public"].Value != Unknown {
		t.Fatal("unknown converted to negative")
	}
	if p.Fresh(time.Unix(161, 0)) || !p.Fresh(time.Unix(160, 0)) {
		t.Fatal("invalid freshness")
	}
	if (DomainEvidence{PartOfDomain: Yes, Match: No}).Result() != No {
		t.Fatal("domain mismatch")
	}
	if (AVEvidence{Installed: Yes, Running: Yes, Updated: Unknown}).Result() != Unknown {
		t.Fatal("AV update unknown")
	}
}
func TestSignedLifecycleAndReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	state := State{DeviceID: "device-a"}
	grant := Grant{DeviceID: "device-a", Tenant: "tenant", Site: "site", Revision: 1, Mode: Temporary, ActivatedAt: 100, ExpiresAt: 200, Action: "activate", Nonce: "one"}
	sign := func(g Grant) SignedGrant {
		b, _ := json.Marshal(g)
		return SignedGrant{Grant: g, Signature: ed25519.Sign(priv, b)}
	}
	if err := state.Apply(pub, sign(grant), 150); err != nil {
		t.Fatal(err)
	}
	if err := state.Apply(pub, sign(grant), 150); err == nil {
		t.Fatal("replay accepted")
	}
	altered := sign(grant)
	altered.Grant.ExpiresAt = 300
	if err := state.Apply(pub, altered, 150); err == nil {
		t.Fatal("tamper accepted")
	}
	wrong := grant
	wrong.DeviceID = "other"
	wrong.Revision = 2
	if err := state.Apply(pub, sign(wrong), 150); err == nil {
		t.Fatal("wrong device accepted")
	}
	if state.Session(201) != Expired || state.Session(199) != Active {
		t.Fatal("expiry incorrect")
	}
	permanent := grant
	permanent.Mode = Permanent
	permanent.ExpiresAt = 0
	permanent.Revision = 2
	permanent.Nonce = "two"
	if err := state.Apply(pub, sign(permanent), 150); err != nil || state.Session(300) != Active {
		t.Fatal("permanent transition")
	}
	auth := permanent
	auth.Action = "uninstall"
	auth.Revision = 3
	auth.Nonce = "three"
	auth.ExpiresAt = 160
	if err := state.Apply(pub, sign(auth), 161); err == nil {
		t.Fatal("expired uninstall accepted")
	}
	if err := state.Apply(pub, sign(auth), 159); err != nil || state.Session(159) != CleanupPending {
		t.Fatal("authorized uninstall failed")
	}
}
