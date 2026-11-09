package servicefactory

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"eguard-nac-agent/servicehost"
)

func (r *env) envelope(action, mode string, rev uint64, activated int64, expires string, at int64, key ed25519.PrivateKey) []byte {
	p := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"grant_id":"%s-%d","revision":%d,"policy_revision":1,"action":%q,"mode":%q,"issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":%s}`,
		binding.Issuer, binding.DeviceID, binding.TenantID, binding.SiteID, binding.EnrollmentID, action, rev, rev, action, mode, at-1, at-1, at+200, activated, expires))
	sig := ed25519.Sign(key, append([]byte("eguard-nac-lifecycle/v1\x00"), p...))
	return []byte(fmt.Sprintf(`{"version":1,"key_id":"life-sf","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
}

func waitDelivery(t *testing.T, r *env) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.received.Load() == 0 {
		t.Fatal("no delivery while active")
	}
}

// Anti-Tamper ON: the admin cannot stop the service, so the signed uninstall
// authorization is handed to the running service (SYSTEM) through the request
// file; the service records it in its journal and runs official cleanup.
func TestUninstallRequestAcceptedByServiceRunsCleanup(t *testing.T) {
	r := setup(t, false)
	now := time.Now().Unix()
	r.accept(t, "activate", "permanent", 1, now-100, "null", now-50)
	d := r.deps()
	d.RequestPoll = 20 * time.Millisecond
	states := make(chan string, 2)
	d.OnTerminal = func(state string, fp [32]byte) error { states <- state; return nil }
	done := make(chan error, 1)
	go func() { done <- servicehost.Run(New(d), make(chan servicehost.Command), nil) }()
	waitDelivery(t, r)
	req := r.envelope("authorize_uninstall", "permanent", 2, now-100, "null", time.Now().Unix(), r.lifeKey)
	if e := os.WriteFile(filepath.Join(r.root, RequestFile), req, 0600); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("service did not act on valid uninstall request")
	}
	if s := <-states; s != StateCleanupIntent {
		t.Fatalf("state=%s", s)
	}
}

// A forged request is rejected, removed, reported, and the service keeps working.
func TestForgedUninstallRequestRejectedServiceContinues(t *testing.T) {
	r := setup(t, false)
	now := time.Now().Unix()
	r.accept(t, "activate", "permanent", 1, now-100, "null", now-50)
	d := r.deps()
	d.RequestPoll = 20 * time.Millisecond
	called := 0
	d.OnTerminal = func(string, [32]byte) error { called++; return nil }
	commands := make(chan servicehost.Command, 1)
	done := make(chan error, 1)
	go func() { done <- servicehost.Run(New(d), commands, nil) }()
	waitDelivery(t, r)
	_, forger, _ := ed25519.GenerateKey(nil)
	req := r.envelope("authorize_uninstall", "permanent", 2, now-100, "null", time.Now().Unix(), forger)
	reqPath := filepath.Join(r.root, RequestFile)
	if e := os.WriteFile(reqPath, req, 0600); e != nil {
		t.Fatal(e)
	}
	resPath := filepath.Join(r.root, ResultFile)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, e := os.ReadFile(resPath); e == nil && len(b) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, _ := os.ReadFile(resPath)
	if len(b) < 8 || string(b[:8]) != "rejected" {
		t.Fatalf("result=%q", b)
	}
	if _, e := os.Stat(reqPath); !os.IsNotExist(e) {
		t.Fatal("rejected request not removed")
	}
	before := r.received.Load()
	deadline = time.Now().Add(5 * time.Second)
	for r.received.Load() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.received.Load() == before {
		t.Fatal("service stopped reporting after rejected request")
	}
	commands <- servicehost.Stop
	<-done
	if called != 0 {
		t.Fatal("cleanup ran on forged request")
	}
}
