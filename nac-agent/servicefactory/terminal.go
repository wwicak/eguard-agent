package servicefactory

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"eguard-nac-agent/bootstrap"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	"eguard-nac-agent/provision"
)

// ErrTerminal is returned by the runner after a signed terminal lifecycle state
// was handed to the cleanup hook.
var ErrTerminal = errors.New("NAC lifecycle terminal; official cleanup invoked")

const (
	StateExpired       = "expired"
	StateCleanupIntent = "cleanup_intent"
)

// terminalAtBoot determines, independently of the machine credential and network,
// whether signed local state already requires cleanup. This is what makes cleanup
// run on the next boot after an expiry that happened while the device was off, and
// after an accepted uninstall authorization (where normal Build refuses to start).
func terminalAtBoot(in provision.Inputs, root string, now time.Time) (string, [32]byte, error) {
	var fp [32]byte
	v, e := bootstrap.Verify(in.BootstrapBytes, in.BootstrapPin, in.State.Binding, in.State.DurableFloor, in.State.JournalPath)
	if e != nil {
		return "", fp, e
	}
	fp = v.MachineCertSHA256()
	b := v.Binding()
	j, e := journal.Open(filepath.Join(root, "journal.db"), journal.Binding{Device: b.DeviceID, Tenant: b.TenantID, Site: b.SiteID, Enrollment: b.EnrollmentID})
	if e != nil {
		return "", fp, e
	}
	defer j.Close()
	keys := v.LifecycleKeys()
	obs, e := lifecycle.Recover(j, keys, b)
	if e != nil {
		return "", fp, e
	}
	switch obs.State {
	case "cleanup_pending", "cleanup_done":
		return StateCleanupIntent, fp, nil
	case "active":
	default:
		return "", fp, nil
	}
	p, e := j.Read()
	if e != nil {
		return "", fp, e
	}
	g, e := lifecycle.VerifyEnvelope(p.Lifecycle.Envelope, keys, b)
	if e != nil {
		return "", fp, e
	}
	var signed struct {
		Mode    string `json:"mode"`
		Expires *int64 `json:"session_expires_at"`
	}
	if e = json.Unmarshal(g.Payload, &signed); e != nil {
		return "", fp, e
	}
	if signed.Mode == "temporary" && signed.Expires != nil && !now.Before(time.Unix(*signed.Expires, 0)) {
		return StateExpired, fp, nil
	}
	return "", fp, nil
}
