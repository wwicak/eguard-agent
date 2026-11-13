// Package bootintegration composes verified components; it does not provision Windows trust or install a service.
package bootintegration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"eguard-nac-agent/bootstrap"
	"eguard-nac-agent/core"
	"eguard-nac-agent/journal"
	"eguard-nac-agent/lifecycle"
	nacruntime "eguard-nac-agent/runtime"
	"eguard-nac-agent/servicehost"
	"eguard-nac-agent/transport"
	"errors"
	"io"
	"sync"
	"time"
)

type Inputs struct {
	RawConfig    []byte
	BootstrapPin ed25519.PublicKey
	Binding      lifecycle.Binding
	DurableFloor uint64
	JournalPath  string
	// These callbacks are trusted installation dependencies, not user-configurable paths or code.
	ResolveJournalPath func(string) (string, error)
	ResolveCredential  func([32]byte) (tls.Certificate, io.Closer, error)
	Now                func() (time.Time, error)
	Collect            func(context.Context) (core.Posture, error)
	// OnLifecycle receives server-supplied signed lifecycle envelopes (untrusted
	// until the caller verifies them). Optional.
	OnLifecycle func([]byte)
	// CollectInventory gathers optional inventory (software / signed-in user)
	// when the signed configuration enables it. Optional.
	CollectInventory func(ctx context.Context, software, user bool) (core.Inventory, error)
	// InventoryInterval: how often inventory is sent (default 1 h);
	// InventoryFirstDelay: delay before the first send (default 20 s).
	InventoryInterval   time.Duration
	InventoryFirstDelay time.Duration
}

var errBoot = errors.New("NAC boot dependencies or evidence invalid")

// Build performs no collection/network or journal creation. The returned close
// function must be called after Run finishes; closing during Run is rejected.
// Clock, revision persistence, CNG and path ACLs remain caller responsibilities.
func Build(in Inputs) (servicehost.Runner, func() error, error) {
	fail := func() (servicehost.Runner, func() error, error) { return nil, nil, errBoot }
	if in.ResolveJournalPath == nil || in.ResolveCredential == nil || in.Now == nil || in.Collect == nil {
		return fail()
	}
	v, e := bootstrap.Verify(in.RawConfig, in.BootstrapPin, in.Binding, in.DurableFloor, in.JournalPath)
	if e != nil {
		return fail()
	}
	now, e := in.Now()
	if e != nil || now.IsZero() {
		return fail()
	}
	path, e := in.ResolveJournalPath(v.JournalPath())
	if e != nil {
		return fail()
	}
	b := v.Binding()
	store, e := journal.Open(path, journal.Binding{Device: b.DeviceID, Tenant: b.TenantID, Site: b.SiteID, Enrollment: b.EnrollmentID})
	if e != nil {
		return fail()
	}
	var credential io.Closer
	success := false
	defer func() {
		if !success {
			if credential != nil {
				_ = credential.Close()
			}
			_ = store.Close()
		}
	}()
	keys := v.LifecycleKeys()
	obs, e := lifecycle.Recover(store, keys, b)
	if e != nil || obs.State != "active" || now.Unix() < obs.ActivatedAt {
		return fail()
	}
	cert, resource, e := in.ResolveCredential(v.MachineCertSHA256())
	credential = resource
	if e != nil || credential == nil || len(cert.Certificate) == 0 || sha256.Sum256(cert.Certificate[0]) != v.MachineCertSHA256() {
		return fail()
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return fail()
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fail()
	}
	public, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return fail()
	}
	// Ignore resolver-supplied parsed Leaf; always use the fingerprint-checked DER.
	cert.Leaf = leaf
	// Re-sample after credential acquisition; never accept a stale boot sample.
	initialTime := now
	now, e = in.Now()
	if e != nil || now.IsZero() || now.Before(initialTime) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA {
		return fail()
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return fail()
	}
	ca, e := x509.ParseCertificate(v.ServerCADER())
	if e != nil {
		return fail()
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	interval, backoff, collectTimeout, sendTimeout := v.Timing()

	// Recheck credential validity at every runtime time gate, including after
	// collection. This also covers reuse of an already established TLS connection.
	var clockMu sync.Mutex
	lastTime := now
	clockInvalid := false
	credentialClock := func() (time.Time, error) {
		clockMu.Lock()
		defer clockMu.Unlock()
		if clockInvalid {
			return time.Time{}, errBoot
		}
		t, err := in.Now()
		if err != nil || t.IsZero() || t.Before(lastTime) || t.Before(leaf.NotBefore) || !t.Before(leaf.NotAfter) {
			clockInvalid = true
			return time.Time{}, errBoot
		}
		lastTime = t
		return t, nil
	}
	client, e := transport.NewClient(transport.Config{Now: credentialClock, BaseURL: v.Origin(), RootCAs: roots, ClientCertificate: cert, Timeout: sendTimeout, OnLifecycle: in.OnLifecycle})
	if e != nil {
		return fail()
	}
	coordinator := &nacruntime.Coordinator{Store: store, Keys: keys, Binding: b, Now: credentialClock, Collect: in.Collect, Send: vpnPostureSender(v.ReportVPN(), client.SendPosture), Interval: interval, Backoff: backoff, CollectTimeout: collectTimeout, SendTimeout: sendTimeout}
	var mu sync.Mutex
	running, closed := false, false
	var closeErr error
	runner := func(ctx context.Context) error {
		mu.Lock()
		if running || closed {
			mu.Unlock()
			return errBoot
		}
		running = true
		mu.Unlock()
		defer func() { mu.Lock(); running = false; mu.Unlock() }()
		if in.CollectInventory != nil && (v.CollectSoftware() || v.CollectUser()) {
			invCtx, stopInv := context.WithCancel(ctx)
			invDone := make(chan struct{})
			go func() {
				defer close(invDone)
				runInventory(invCtx, in, client, credentialClock, v.CollectSoftware(), v.CollectUser(), collectTimeout, sendTimeout)
			}()
			defer func() { stopInv(); <-invDone }()
		}
		return coordinator.Run(ctx)
	}
	closeFn := func() error {
		mu.Lock()
		defer mu.Unlock()
		if running {
			return errBoot
		}
		if closed {
			return closeErr
		}
		closed = true
		client.CloseIdleConnections()
		closeErr = errors.Join(credential.Close(), store.Close())
		return closeErr
	}
	success = true
	return runner, closeFn, nil
}

// runInventory sends inventory shortly after start and then every interval.
// Failures are retried at the next interval; posture is never affected.
func runInventory(ctx context.Context, in Inputs, client *transport.Client, now func() (time.Time, error), software, user bool, collectTimeout, sendTimeout time.Duration) {
	every := in.InventoryInterval
	if every <= 0 {
		every = time.Hour
	}
	wait := in.InventoryFirstDelay
	if wait <= 0 {
		wait = 20 * time.Second
	}
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		wait = every
		if _, err := now(); err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 2*collectTimeout)
		inv, err := in.CollectInventory(cctx, software, user)
		cancel()
		if err != nil {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 2*sendTimeout)
		_ = client.SendInventory(sctx, inv)
		cancel()
	}
}
