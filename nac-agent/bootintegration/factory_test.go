package bootintegration

// Proposed production API, absent today: Build(Inputs) (servicehost.Runner, func() error, error).
// Inputs contains RawConfig, BootstrapPin, Binding, DurableFloor, JournalPath,
// ResolveJournalPath (installation-owned Windows path -> existing local path;
// Linux test adapter ONLY), ResolveCredential (fingerprint -> tls.Certificate,
// io.Closer, error), Now (trusted time), Collect (context -> core.Posture).
// Close owns the opened journal and credential and is safe once after Run.
// No boolean verified shortcut, no journal creation, no default trust/clock.

import (
	"bytes"
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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"eguard-nac-agent/core"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	"eguard-nac-agent/servicehost"
)

const installedPath = `C:\ProgramData\eGuardNAC\state.db`
const issuedAt int64 = 1700000000

var bound = lifecycle.Binding{Issuer: "issuer-test", DeviceID: "device-test", TenantID: "tenant-test", SiteID: "site-test", EnrollmentID: "enrollment-test"}

func journalBinding() journal.Binding {
	return journal.Binding{Device: bound.DeviceID, Tenant: bound.TenantID, Site: bound.SiteID, Enrollment: bound.EnrollmentID}
}

type closedResource struct{ n atomic.Int32 }

func (c *closedResource) Close() error { c.n.Add(1); return nil }

type rig struct {
	t            *testing.T
	bootKey      ed25519.PrivateKey
	bootPub      ed25519.PublicKey
	lifecycleKey ed25519.PrivateKey
	lifecyclePub ed25519.PublicKey
	caDER        []byte
	caKey        ed25519.PrivateKey
	cert         tls.Certificate
	leaf         []byte
	origin       string
	server       *httptest.Server
	disk         string
	acquired     *closedResource
	resolved     atomic.Bool
	collected    atomic.Int32
	received     atomic.Int32
	inventory    atomic.Int32
	invFlags     string // extra signed bootstrap fields, e.g. `"collect_software":"on",`
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return p, k
}
func cert(t *testing.T, template, parent *x509.Certificate, pub ed25519.PublicKey, signer ed25519.PrivateKey) []byte {
	t.Helper()
	b, e := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, acquired: &closedResource{}, disk: filepath.Join(t.TempDir(), "state.db")}
	r.bootPub, r.bootKey = key(t)
	r.lifecyclePub, r.lifecycleKey = key(t)
	caPub, caKey := key(t)
	r.caKey = caKey
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	r.caDER = cert(t, ca, ca, caPub, caKey)
	clientPub, clientKey := key(t)
	client := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test client"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	r.leaf = cert(t, client, ca, clientPub, caKey)
	r.cert = tls.Certificate{Certificate: [][]byte{r.leaf, r.caDER}, PrivateKey: clientKey}
	serverPub, serverKey := key(t)
	serverCert := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{"localhost"}, IPAddresses: nil, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	// httptest uses 127.0.0.1 by default; set SAN for the loopback host.
	serverCert.DNSNames = nil
	serverCert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	serverDER := cert(t, serverCert, ca, serverPub, caKey)
	pool := x509.NewCertPool()
	root, e := x509.ParseCertificate(r.caDER)
	if e != nil {
		t.Fatal(e)
	}
	pool.AddCert(root)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v1/nac/inventory" && req.Method == "POST" && req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			r.inventory.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"accepted":true}`)
			return
		}
		if req.URL.Path != "/v1/nac/posture" || req.Method != "POST" || req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.PeerCertificates) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER, r.caDER}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	r.server = s
	r.origin = s.URL
	t.Cleanup(s.Close)
	return r
}
func (r *rig) bootstrap() []byte {
	r.t.Helper()
	fp := sha256.Sum256(r.leaf)
	payload := []byte(fmt.Sprintf(`{`+r.invFlags+`"version":1,"purpose":"eguard-nac-boot-config","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"revision":7,"https_origin":%q,"server_ca_der_b64":%q,"lifecycle_keys":{"lifecycle-1":%q},"machine_cert_sha256":%q,"journal_path":%q,"interval_seconds":60,"backoff_seconds":5,"collect_timeout_seconds":12,"send_timeout_seconds":10}`,
		bound.Issuer, bound.DeviceID, bound.TenantID, bound.SiteID, bound.EnrollmentID, r.origin, base64.StdEncoding.EncodeToString(r.caDER), base64.StdEncoding.EncodeToString(r.lifecyclePub), hex.EncodeToString(fp[:]), installedPath))
	sig := ed25519.Sign(r.bootKey, append([]byte("eguard-nac-boot-config/v1\x00"), payload...))
	return []byte(fmt.Sprintf(`{"version":1,"payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(sig)))
}
func (r *rig) lifecycleEnvelope() []byte {
	p := []byte(fmt.Sprintf(`{"protocol_version":1,"purpose":"eguard-nac-lifecycle","issuer":%q,"device_id":%q,"tenant_id":%q,"site_id":%q,"enrollment_id":%q,"grant_id":"activate-1","revision":1,"policy_revision":1,"action":"activate","mode":"permanent","issued_at":%d,"not_before":%d,"valid_until":%d,"activated_at":%d,"session_expires_at":null}`,
		bound.Issuer, bound.DeviceID, bound.TenantID, bound.SiteID, bound.EnrollmentID, issuedAt, issuedAt, issuedAt+60, issuedAt-10))
	sig := ed25519.Sign(r.lifecycleKey, append([]byte("eguard-nac-lifecycle/v1\x00"), p...))
	return []byte(fmt.Sprintf(`{"version":1,"key_id":"lifecycle-1","payload_b64":%q,"signature_b64":%q}`, base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(sig)))
}
func (r *rig) createJournal(t *testing.T) {
	t.Helper()
	s, e := journal.Create(r.disk, journalBinding())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lifecycle.Accept(s, r.lifecycleEnvelope(), map[string]ed25519.PublicKey{"lifecycle-1": r.lifecyclePub}, bound, issuedAt); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
}
func (r *rig) inputs() Inputs {
	return Inputs{
		RawConfig: r.bootstrap(), BootstrapPin: r.bootPub, Binding: bound, DurableFloor: 7, JournalPath: installedPath,
		ResolveJournalPath: func(p string) (string, error) {
			if p != installedPath {
				return "", errors.New("untrusted path")
			}
			return r.disk, nil
		},
		ResolveCredential: func(fp [32]byte) (tls.Certificate, io.Closer, error) {
			r.acquired = &closedResource{}
			r.resolved.Store(true)
			return r.cert, r.acquired, nil
		},
		Now: func() (time.Time, error) { return time.Now(), nil },
		Collect: func(ctx context.Context) (core.Posture, error) {
			r.collected.Add(1)
			return core.Posture{AgentType: "nac", ObservedAt: time.Now(), TTL: time.Minute}, nil
		},
	}
}
func runOnce(t *testing.T, runner servicehost.Runner, received *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner(ctx) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for received.Load() == 0 {
		select {
		case <-deadline.C:
			cancel()
			<-done
			t.Fatal("runner failed to send")
		case <-done:
			t.Fatal("runner exited before stop")
		case <-time.After(time.Millisecond * 5):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runner ignored cancellation")
	}
}

func TestConnectedSignedBootDiskLifecycleAndMTLS(t *testing.T) {
	r := newRig(t)
	r.createJournal(t)
	in := r.inputs()
	runner, closeFn, e := Build(in)
	if e != nil {
		t.Fatal(e)
	}
	if runner == nil || closeFn == nil {
		t.Fatal("missing owned runner/close")
	}
	runOnce(t, runner, &r.received)
	if r.collected.Load() == 0 || r.received.Load() == 0 {
		t.Fatal("no signed lifecycle gated posture delivered by mTLS")
	}
	if e := closeFn(); e != nil {
		t.Fatal(e)
	}
	if r.acquired.n.Load() != 1 {
		t.Fatal("credential resource not closed exactly once")
	}
	s, e := journal.Open(r.disk, journalBinding())
	if e != nil {
		t.Fatal("opened journal not released")
	}
	_ = s.Close()
}
func TestBootFailureNeverCollectsOrSendsAndReleasesResources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *rig, *Inputs)
	}{
		{"zero raw config", func(t *testing.T, r *rig, i *Inputs) { i.RawConfig = nil }},
		{"tampered signature", func(t *testing.T, r *rig, i *Inputs) {
			i.RawConfig = bytes.Clone(i.RawConfig)
			i.RawConfig[len(i.RawConfig)-4] ^= 1
		}},
		{"cross binding", func(t *testing.T, r *rig, i *Inputs) { i.Binding.TenantID = "other" }},
		{"revision rollback", func(t *testing.T, r *rig, i *Inputs) { i.DurableFloor = 8 }},
		{"wrong journal binding", func(t *testing.T, r *rig, i *Inputs) {
			s, e := journal.Create(r.disk, journal.Binding{Device: "other", Tenant: bound.TenantID, Site: bound.SiteID, Enrollment: bound.EnrollmentID})
			if e != nil {
				t.Fatal(e)
			}
			_ = s.Close()
		}},
		{"unknown trusted clock", func(t *testing.T, r *rig, i *Inputs) {
			i.Now = func() (time.Time, error) { return time.Time{}, errors.New("clock ambiguous") }
		}},
		{"wrong fingerprint", func(t *testing.T, r *rig, i *Inputs) {
			p, k := key(t)
			c := &x509.Certificate{SerialNumber: big.NewInt(31), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			root, _ := x509.ParseCertificate(r.caDER)
			der := cert(t, c, root, p, r.caKey)
			i.ResolveCredential = func([32]byte) (tls.Certificate, io.Closer, error) {
				r.acquired = &closedResource{}
				r.resolved.Store(true)
				return tls.Certificate{Certificate: [][]byte{der, r.caDER}, PrivateKey: k}, r.acquired, nil
			}
		}},
		{"wrong certificate key", func(t *testing.T, r *rig, i *Inputs) {
			_, k := key(t)
			i.ResolveCredential = func([32]byte) (tls.Certificate, io.Closer, error) {
				r.acquired = &closedResource{}
				r.resolved.Store(true)
				c := r.cert
				c.PrivateKey = k
				return c, r.acquired, nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			if tc.name != "wrong journal binding" {
				r.createJournal(t)
			}
			i := r.inputs()
			tc.change(t, r, &i)
			runner, closeFn, e := Build(i)
			if e == nil || runner != nil || closeFn != nil {
				if closeFn != nil {
					_ = closeFn()
				}
				t.Fatal("invalid boot returned runner")
			}
			if r.collected.Load() != 0 || r.received.Load() != 0 {
				t.Fatal("side effect before verification")
			}
			if r.resolved.Load() && r.acquired.n.Load() != 1 {
				t.Fatal("acquired credential not released exactly once on failure")
			}
			// An existing journal must be reopenable after failure (no leaked lock).
			if tc.name != "wrong journal binding" {
				s, err := journal.Open(r.disk, journalBinding())
				if err != nil {
					t.Fatal("journal leaked", err)
				}
				_ = s.Close()
			}
		})
	}
}
func TestMissingJournalIsNeverCreated(t *testing.T) {
	r := newRig(t)
	i := r.inputs()
	if runner, closeFn, e := Build(i); e == nil || runner != nil || closeFn != nil {
		t.Fatal("missing journal boot succeeded")
	}
	if _, e := os.Stat(r.disk); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("factory created missing journal")
	}
	if r.collected.Load() != 0 || r.received.Load() != 0 {
		t.Fatal("side effects on missing journal")
	}
}
func TestServiceHostUsesOnlyVerifiedFactory(t *testing.T) {
	r := newRig(t)
	r.createJournal(t)
	in := r.inputs()
	var closer func() error
	commands := make(chan servicehost.Command, 1)
	commands <- servicehost.Stop
	var running bool
	err := servicehost.Run(func() (servicehost.Runner, error) {
		runner, closeFn, e := Build(in)
		closer = closeFn
		return runner, e
	}, commands, func(s servicehost.Status) {
		if s == servicehost.Running {
			running = true
		}
	})
	if err != nil || !running || closer == nil {
		t.Fatalf("service host failed verified factory: %v", err)
	}
	if e := closer(); e != nil {
		t.Fatal(e)
	}
	r2 := newRig(t)
	invalid := r2.inputs()
	invalid.RawConfig = nil
	running = false
	err = servicehost.Run(func() (servicehost.Runner, error) {
		runner, closeFn, e := Build(invalid)
		if closeFn != nil {
			_ = closeFn()
		}
		return runner, e
	}, nil, func(s servicehost.Status) {
		if s == servicehost.Running {
			running = true
		}
	})
	if err == nil || running || r2.collected.Load() != 0 || r2.received.Load() != 0 {
		t.Fatal("service Running or side effects on invalid bootstrap")
	}
}

func TestInventoryOnlyWhenSignedConfigEnablesIt(t *testing.T) {
	for _, tc := range []struct {
		flags string
		want  bool
	}{{"", false}, {`"collect_software":"off","collect_user":"off",`, false}, {`"collect_software":"on",`, true}} {
		r := newRig(t)
		r.invFlags = tc.flags
		r.createJournal(t)
		var gotSoftware, gotUser bool
		in := r.inputs()
		in.InventoryInterval = 50 * time.Millisecond
		in.InventoryFirstDelay = 10 * time.Millisecond
		in.CollectInventory = func(ctx context.Context, software, user bool) (core.Inventory, error) {
			gotSoftware, gotUser = software, user
			return core.Inventory{AgentType: "nac", ObservedAt: time.Now().UTC(), SoftwareCollected: software, Software: []core.SoftwareItem{}}, nil
		}
		run, closeFn, err := Build(in)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		_ = run(ctx)
		cancel()
		_ = closeFn()
		if (r.inventory.Load() > 0) != tc.want || (tc.want && (!gotSoftware || gotUser)) {
			t.Fatalf("flags %q: sent=%d software=%v user=%v", tc.flags, r.inventory.Load(), gotSoftware, gotUser)
		}
	}
}
