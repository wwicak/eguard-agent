package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"eguard-nac-agent/core"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
)

const stamp int64 = 1700000000

func signedFixture(t *testing.T, mode, action string, expires int64) (*journal.Store, map[string]ed25519.PublicKey, lifecycle.Binding) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	keys := map[string]ed25519.PublicKey{"test": pub}
	binding := lifecycle.Binding{Issuer: "fixture", DeviceID: "device", TenantID: "tenant", SiteID: "site", EnrollmentID: "enroll"}
	s, e := journal.Create(filepath.Join(t.TempDir(), "db"), journal.Binding{Device: "device", Tenant: "tenant", Site: "site", Enrollment: "enroll"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	expiry := "null"
	if mode == "temporary" {
		expiry = fmt.Sprint(expires)
	}
	raw := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":"fixture","device_id":"device","tenant_id":"tenant","site_id":"site","enrollment_id":"enroll","grant_id":"first","revision":1,"policy_revision":1,"action":"activate","mode":%q,"issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":%s}`, mode, stamp, stamp, stamp+60, stamp-10, expiry))
	envelope := func(p []byte) []byte {
		return []byte(fmt.Sprintf(`{"version":1,"key_id":"test","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte("eguard-nac-lifecycle/v1\x00"), p...)))))
	}
	if action != "pending" {
		if _, e = lifecycle.Accept(s, envelope(raw), keys, binding, stamp+1); e != nil {
			t.Fatal(e)
		}
	}
	if action == "revoke" || action == "authorize_uninstall" {
		raw = []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":"fixture","device_id":"device","tenant_id":"tenant","site_id":"site","enrollment_id":"enroll","grant_id":"second","revision":2,"policy_revision":1,"action":%q,"mode":%q,"issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":%s}`, action, mode, stamp+2, stamp+2, stamp+60, stamp-10, expiry))
		if _, e = lifecycle.Accept(s, envelope(raw), keys, binding, stamp+3); e != nil {
			t.Fatal(e)
		}
	}
	return s, keys, binding
}
func mk(t *testing.T, mode, action string, expires int64, now *time.Time, collect func(context.Context) (core.Posture, error), send func(context.Context, core.Posture) error) *Coordinator {
	t.Helper()
	s, keys, b := signedFixture(t, mode, action, expires)
	return &Coordinator{Store: s, Keys: keys, Binding: b, Now: func() (time.Time, error) { return *now, nil }, Collect: collect, Send: send, Interval: time.Millisecond * 10, Backoff: time.Millisecond * 20, CollectTimeout: time.Second, SendTimeout: time.Second}
}
func evidence(at time.Time) core.Posture {
	return core.Posture{AgentType: "nac", OS: "fixture", ObservedAt: at, TTL: time.Minute, Firewall: map[string]core.Evidence{}, Adapters: []core.Adapter{}}
}
func TestVerifiedStateGatesCollectionAndSending(t *testing.T) {
	for _, tc := range []struct {
		mode, action string
		expires      int64
		want         State
	}{{"temporary", "pending", stamp + 60, Pending}, {"temporary", "revoke", stamp + 60, Revoked},
		{"temporary", "authorize_uninstall", stamp + 60, CleanupIntent}, {"temporary", "active", stamp + 5, Expired}, {"permanent", "active", 0, Active}} {
		t.Run(string(tc.want)+tc.action, func(t *testing.T) {
			now := time.Unix(stamp+20, 0)
			var calls atomic.Int32
			c := mk(t, tc.mode, tc.action, tc.expires, &now, func(context.Context) (core.Posture, error) { calls.Add(1); return evidence(now), nil }, func(context.Context, core.Posture) error { calls.Add(10); return nil })
			state, e := c.Tick(context.Background())
			if e != nil || state != tc.want {
				t.Fatalf("state=%q err=%v want=%q", state, e, tc.want)
			}
			want := int32(0)
			if tc.want == Active {
				want = 11
			}
			if calls.Load() != want {
				t.Fatalf("side effects=%d want %d", calls.Load(), want)
			}
		})
	}
}
func TestTemporaryDeadlineCheckedAfterCollectionAndNoFabricatedFreshness(t *testing.T) {
	now := time.Unix(stamp+2, 0)
	var sends atomic.Int32
	c := mk(t, "temporary", "active", stamp+10, &now, func(context.Context) (core.Posture, error) {
		p := evidence(now)
		now = time.Unix(stamp+10, 0)
		return p, nil
	}, func(context.Context, core.Posture) error { sends.Add(1); return nil })
	state, e := c.Tick(context.Background())
	if e != nil || state != Expired || sends.Load() != 0 {
		t.Fatalf("deadline ignored: %s %v", state, e)
	}
	now = time.Unix(stamp+2, 0)
	c.Collect = func(context.Context) (core.Posture, error) { return evidence(now.Add(-2 * time.Minute)), nil }
	state, e = c.Tick(context.Background())
	if e == nil || state != Stale || sends.Load() != 0 {
		t.Fatalf("stale sent: %s %v", state, e)
	}
}
func TestSingleFlightCancellationAndOutageNoLocalAction(t *testing.T) {
	now := time.Unix(stamp+2, 0)
	entered := make(chan struct{})
	release := make(chan struct{})
	var sends atomic.Int32
	c := mk(t, "permanent", "active", 0, &now, func(ctx context.Context) (core.Posture, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return core.Posture{}, ctx.Err()
		case <-release:
			return evidence(now), nil
		}
	}, func(context.Context, core.Posture) error { sends.Add(1); return fmt.Errorf("offline") })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _ = c.Tick(ctx) }()
	<-entered
	if state, e := c.Tick(context.Background()); state != Busy || e != nil {
		t.Fatalf("overlap: %s %v", state, e)
	}
	cancel()
	<-done
	if sends.Load() != 0 {
		t.Fatal("canceled collection sent")
	}
	close(release)
	c.Collect = func(context.Context) (core.Posture, error) { return evidence(now), nil }
	state, e := c.Tick(context.Background())
	if state != Outage || e == nil || sends.Load() != 1 {
		t.Fatalf("outage state=%s error=%v sends=%d", state, e, sends.Load())
	}
}
func TestOriginalObservationTimePreserved(t *testing.T) {
	now := time.Unix(stamp+10, 0)
	original := now.Add(-time.Second)
	var got time.Time
	c := mk(t, "permanent", "active", 0, &now, func(context.Context) (core.Posture, error) { return evidence(original), nil }, func(_ context.Context, p core.Posture) error { got = p.ObservedAt; return nil })
	state, e := c.Tick(context.Background())
	if state != Active || e != nil || !got.Equal(original) {
		t.Fatal(state, e)
	}
}
func TestRunStopsPromptlyAndBacksOff(t *testing.T) {
	now := time.Unix(stamp+2, 0)
	var calls atomic.Int32
	c := mk(t, "permanent", "active", 0, &now, func(context.Context) (core.Posture, error) { calls.Add(1); return evidence(now), nil }, func(context.Context, core.Posture) error { return fmt.Errorf("outage") })
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	if e := c.Run(ctx); e != context.DeadlineExceeded {
		t.Fatal(e)
	}
	if n := calls.Load(); n < 1 || n > 5 {
		t.Fatalf("backoff unbounded or no ticks: %d", n)
	}
}
