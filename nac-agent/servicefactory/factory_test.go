package servicefactory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"eguard-nac-agent/core"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/servicehost"
)

var binding = lifecycle.Binding{Issuer: "issuer-sf", DeviceID: "device-sf", TenantID: "tenant-sf", SiteID: "site-sf", EnrollmentID: "enroll-sf"}

type closer struct{ n atomic.Int32 }

func (c *closer) Close() error { c.n.Add(1); return nil }

type env struct {
	root                string
	bootKey, lifeKey    ed25519.PrivateKey
	lifePub             ed25519.PublicKey
	caDER, leaf         []byte
	cert                tls.Certificate
	origin              string
	received, collected atomic.Int32
	serverLifecycle     atomic.Pointer[[]byte]
	cred                closer
}

func mk(t *testing.T, tmpl, parent *x509.Certificate, pub ed25519.PublicKey, key ed25519.PrivateKey) []byte {
	t.Helper()
	b, e := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func setup(t *testing.T, withLifecycle bool) *env {
	t.Helper()
	r := &env{root: t.TempDir()}
	bootPub, bootKey, _ := ed25519.GenerateKey(rand.Reader)
	r.bootKey = bootKey
	provision.BootstrapPinHex = hex.EncodeToString(bootPub)
	t.Cleanup(func() { provision.BootstrapPinHex = "" })
	r.lifePub, r.lifeKey, _ = ed25519.GenerateKey(rand.Reader)
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sf root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	r.caDER = mk(t, ca, ca, caPub, caKey)
	clientPub, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	r.leaf = mk(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sf client"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, ca, clientPub, caKey)
	r.cert = tls.Certificate{Certificate: [][]byte{r.leaf, r.caDER}, PrivateKey: clientKey}
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	serverDER := mk(t, &x509.Certificate{SerialNumber: big.NewInt(3), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, ca, serverPub, caKey)
	root, _ := x509.ParseCertificate(r.caDER)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/nac/posture" || req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if v := r.serverLifecycle.Load(); v != nil {
			_, _ = io.WriteString(w, `{"accepted":true,"lifecycle":"`+base64.RawURLEncoding.EncodeToString(*v)+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER, r.caDER}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	t.Cleanup(s.Close)
	r.origin = s.URL

	state := provision.State{Version: 1, Binding: binding, DurableFloor: 1, JournalPath: provision.JournalPath}
	if e := provision.Write(r.root, state, r.bootstrap()); e != nil {
		t.Fatal(e)
	}
	if withLifecycle {
		j, e := journal.Open(r.root+"/journal.db", journal.Binding{Device: binding.DeviceID, Tenant: binding.TenantID, Site: binding.SiteID, Enrollment: binding.EnrollmentID})
		if e != nil {
			t.Fatal(e)
		}
		at := time.Now().Unix()
		p := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"grant_id":"activate-sf","revision":1,"policy_revision":1,"action":"activate","mode":"permanent","issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":null}`,
			binding.Issuer, binding.DeviceID, binding.TenantID, binding.SiteID, binding.EnrollmentID, at-1, at-1, at+60, at-1))
		sig := ed25519.Sign(r.lifeKey, append([]byte("eguard-nac-lifecycle/v1\x00"), p...))
		envl := []byte(fmt.Sprintf(`{"version":1,"key_id":"life-sf","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
		if _, e = lifecycle.Accept(j, envl, map[string]ed25519.PublicKey{"life-sf": r.lifePub}, binding, at); e != nil {
			t.Fatal(e)
		}
		_ = j.Close()
	}
	return r
}

func (r *env) bootstrap() []byte {
	fp := sha256.Sum256(r.leaf)
	p := []byte(fmt.Sprintf(`{"version":1,"purpose":"eguard-nac-boot-config","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"revision":1,"https_origin":%q,"server_ca_der_b64":%q,"lifecycle_keys":{"life-sf":%q},"machine_cert_sha256":%q,"journal_path":%q,"interval_seconds":1,"backoff_seconds":1,"collect_timeout_seconds":10,"send_timeout_seconds":10}`,
		binding.Issuer, binding.DeviceID, binding.TenantID, binding.SiteID, binding.EnrollmentID, r.origin, base64.StdEncoding.EncodeToString(r.caDER), base64.StdEncoding.EncodeToString(r.lifePub), hex.EncodeToString(fp[:]), provision.JournalPath))
	sig := ed25519.Sign(r.bootKey, append([]byte("eguard-nac-boot-config/v1\x00"), p...))
	return []byte(fmt.Sprintf(`{"version":1,"payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
}

// writeGrant appends a signed lifecycle transition to the provisioned journal.
func (r *env) accept(t *testing.T, action, mode string, rev uint64, activated int64, expires string, at int64) {
	t.Helper()
	j, e := journal.Open(r.root+"/journal.db", journal.Binding{Device: binding.DeviceID, Tenant: binding.TenantID, Site: binding.SiteID, Enrollment: binding.EnrollmentID})
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	p := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"grant_id":"%s-%d","revision":%d,"policy_revision":1,"action":%q,"mode":%q,"issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":%s}`,
		binding.Issuer, binding.DeviceID, binding.TenantID, binding.SiteID, binding.EnrollmentID, action, rev, rev, action, mode, at-1, at-1, at+200, activated, expires))
	sig := ed25519.Sign(r.lifeKey, append([]byte("eguard-nac-lifecycle/v1\x00"), p...))
	envl := []byte(fmt.Sprintf(`{"version":1,"key_id":"life-sf","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
	if _, e = lifecycle.Accept(j, envl, map[string]ed25519.PublicKey{"life-sf": r.lifePub}, binding, at); e != nil {
		t.Fatal(e)
	}
}

func (r *env) deps() Deps {
	return Deps{
		Root: r.root,
		ResolveCredential: func(fp [32]byte) (tls.Certificate, io.Closer, error) {
			if fp != sha256.Sum256(r.leaf) {
				return tls.Certificate{}, nil, errors.New("no such credential")
			}
			return r.cert, &r.cred, nil
		},
		Now: func() (time.Time, error) { return time.Now(), nil },
		Collect: func(context.Context) (core.Posture, error) {
			r.collected.Add(1)
			return core.Posture{AgentType: "nac", Domain: core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown}, AV: core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown}, Firewall: map[string]core.Evidence{}, OS: "test", ObservedAt: time.Now(), TTL: 5 * time.Minute}, nil
		},
	}
}

// Provisioned store → signed bootstrap → signed lifecycle → mTLS delivery, via the
// real servicehost lifecycle; credential released exactly once after stop.
func TestProvisionedFactoryRunsAndReleases(t *testing.T) {
	r := setup(t, true)
	commands := make(chan servicehost.Command, 1)
	var running atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- servicehost.Run(New(r.deps()), commands, func(s servicehost.Status) {
			if s == servicehost.Running {
				running.Store(true)
			}
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.received.Load() == 0 || r.collected.Load() == 0 || !running.Load() {
		t.Fatalf("no delivery: received=%d collected=%d running=%v", r.received.Load(), r.collected.Load(), running.Load())
	}
	commands <- servicehost.Stop
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service did not stop")
	}
	if r.cred.n.Load() != 1 {
		t.Fatalf("credential closed %d times", r.cred.n.Load())
	}
}

// Missing pin, missing lifecycle activation, unknown credential: factory fails
// before Running and never collects or sends.
func TestFactoryFailsClosed(t *testing.T) {
	cases := map[string]func(*env, *Deps){
		"no pin":        func(r *env, d *Deps) { provision.BootstrapPinHex = "" },
		"no activation": nil,
		"wrong credential": func(r *env, d *Deps) {
			d.ResolveCredential = func([32]byte) (tls.Certificate, io.Closer, error) {
				return tls.Certificate{}, nil, errors.New("absent")
			}
		},
		"empty root": func(r *env, d *Deps) { d.Root = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := setup(t, name != "no activation")
			d := r.deps()
			if mutate != nil {
				mutate(r, &d)
			}
			var running atomic.Bool
			e := servicehost.Run(New(d), make(chan servicehost.Command), func(s servicehost.Status) {
				if s == servicehost.Running {
					running.Store(true)
				}
			})
			if e == nil || running.Load() || r.collected.Load() != 0 || r.received.Load() != 0 {
				t.Fatalf("err=%v running=%v collected=%d received=%d", e, running.Load(), r.collected.Load(), r.received.Load())
			}
		})
	}
}

// A signed terminal state ends the service runner and hands the verified machine
// certificate fingerprint to the cleanup hook; nothing is collected or sent.
func TestTerminalStateInvokesCleanupWithVerifiedFingerprint(t *testing.T) {
	r := setup(t, false)
	now := time.Now().Unix()
	// Temporary session already past its signed expiry when the service starts.
	r.accept(t, "activate", "temporary", 1, now-100, fmt.Sprint(now-10), now-50)
	d := r.deps()
	var gotFP [32]byte
	var gotState string
	calls := 0
	d.OnTerminal = func(state string, fp [32]byte) error { calls++; gotState, gotFP = state, fp; return nil }
	e := servicehost.Run(New(d), make(chan servicehost.Command), nil)
	if e != nil && !errors.Is(e, ErrTerminal) {
		t.Fatalf("run: %v", e)
	}
	if calls != 1 || gotState != "expired" || gotFP != sha256.Sum256(r.leaf) {
		t.Fatalf("calls=%d state=%q fpOK=%v", calls, gotState, gotFP == sha256.Sum256(r.leaf))
	}
	if r.collected.Load() != 0 || r.received.Load() != 0 {
		t.Fatal("collected/sent after expiry")
	}
	// Boot-time terminal path must not even acquire the machine credential.
	if r.cred.n.Load() != 0 {
		t.Fatalf("credential touched %d times on terminal boot", r.cred.n.Load())
	}
}

// Expiry reached while running: coordinator ends, credential+journal are released
// exactly once BEFORE the cleanup hook runs (cleanup deletes them).
func TestExpiryDuringRunReleasesThenCleans(t *testing.T) {
	r := setup(t, false)
	start := time.Now().Unix()
	r.accept(t, "activate", "temporary", 1, start-5, fmt.Sprint(start+600), start-1)
	d := r.deps()
	var mu sync.Mutex
	fake := time.Now()
	d.Now = func() (time.Time, error) { mu.Lock(); defer mu.Unlock(); return fake, nil }
	d.Collect = func(context.Context) (core.Posture, error) {
		r.collected.Add(1)
		mu.Lock()
		at := fake
		mu.Unlock()
		return core.Posture{AgentType: "nac", Domain: core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown}, AV: core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown}, Firewall: map[string]core.Evidence{}, OS: "test", ObservedAt: at, TTL: 5 * time.Minute}, nil
	}
	closedAtCleanup := int32(-1)
	d.OnTerminal = func(state string, fp [32]byte) error {
		closedAtCleanup = r.cred.n.Load()
		if state != StateExpired {
			t.Errorf("state=%s", state)
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- servicehost.Run(New(d), make(chan servicehost.Command), nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for r.received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.received.Load() == 0 {
		t.Fatal("no delivery while active")
	}
	mu.Lock()
	fake = fake.Add(601 * time.Second) // forward only: rollback latch stays satisfied
	mu.Unlock()
	select {
	case <-done:
	case <-time.After(70 * time.Second):
		t.Fatal("service did not end at signed expiry")
	}
	if closedAtCleanup != 1 {
		t.Fatalf("credential closes at cleanup time=%d, want 1", closedAtCleanup)
	}
}

// Without a hook, terminal state still stops (never loops forever reporting).
func TestTerminalWithoutHookStops(t *testing.T) {
	r := setup(t, false)
	now := time.Now().Unix()
	r.accept(t, "activate", "temporary", 1, now-100, fmt.Sprint(now-10), now-50)
	done := make(chan error, 1)
	go func() { done <- servicehost.Run(New(r.deps()), make(chan servicehost.Command), nil) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("service kept running after signed expiry")
	}
}
