// Package admission is the installer-side gate required by provision.Write: it
// verifies enrollment material before anything is written to the provisioning store.
package admission

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"eguard-nac-agent/bootstrap"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	"eguard-nac-agent/provision"
)

var ErrRejected = errors.New("enrollment material rejected")

// claimedBinding reads binding fields only to choose the expected binding;
// bootstrap.Verify then authenticates the exact payload bytes with the build-time
// pin, so a forged or edited binding cannot pass.
func claimedBinding(raw []byte) (lifecycle.Binding, error) {
	var env struct {
		Payload string `json:"payload_b64"`
	}
	if len(raw) > 256*1024 || json.Unmarshal(raw, &env) != nil {
		return lifecycle.Binding{}, ErrRejected
	}
	p, e := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if e != nil {
		return lifecycle.Binding{}, ErrRejected
	}
	var f struct {
		Issuer       string `json:"issuer"`
		DeviceID     string `json:"device_id"`
		TenantID     string `json:"tenant_id"`
		SiteID       string `json:"site_id"`
		EnrollmentID string `json:"enrollment_id"`
	}
	if json.Unmarshal(p, &f) != nil {
		return lifecycle.Binding{}, ErrRejected
	}
	return lifecycle.Binding{Issuer: f.Issuer, DeviceID: f.DeviceID, TenantID: f.TenantID, SiteID: f.SiteID, EnrollmentID: f.EnrollmentID}, nil
}

// Install verifies the signed bootstrap (pin, binding, fixed journal path) and the
// signed activation grant, and only then writes the provisioning store and accepts
// the activation into the newly created journal. now must be a trusted time.
// Installer-level authorization (elevation, operator consent) is the caller's job.
func Install(root string, bootstrapRaw, activationRaw []byte, now time.Time) (lifecycle.Observation, error) {
	var zero lifecycle.Observation
	pin, e := provision.Pin()
	if e != nil {
		return zero, e
	}
	b, e := claimedBinding(bootstrapRaw)
	if e != nil {
		return zero, e
	}
	v, e := bootstrap.Verify(bootstrapRaw, pin, b, 1, provision.JournalPath)
	if e != nil {
		return zero, ErrRejected
	}
	keys := v.LifecycleKeys()
	g, e := lifecycle.VerifyEnvelope(activationRaw, keys, b)
	if e != nil || g.Action != "activate" || lifecycle.ValidateAcceptance(g, now.Unix()) != nil {
		return zero, ErrRejected
	}
	state := provision.State{Version: 1, Binding: b, DurableFloor: v.Revision(), JournalPath: provision.JournalPath}
	if e = provision.Write(root, state, bootstrapRaw); e != nil {
		return zero, e
	}
	j, e := journal.Open(filepath.Join(root, "journal.db"), journal.Binding{Device: b.DeviceID, Tenant: b.TenantID, Site: b.SiteID, Enrollment: b.EnrollmentID})
	if e != nil {
		return zero, e
	}
	obs, e := lifecycle.Accept(j, activationRaw, keys, b, now.Unix())
	return obs, errors.Join(e, j.Close())
}
