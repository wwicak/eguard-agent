package transport

// Proposed test-only contract (production implementation deliberately absent):
// NewClient(Config{BaseURL string, RootCAs *x509.CertPool,
// ClientCertificate tls.Certificate, Timeout time.Duration}) (*Client, error)
// (*Client).SendPosture(context.Context, core.Posture) error
// Client POSTs JSON only to BaseURL + "/v1/nac/posture". It never follows
// redirects or interprets assignment/identity in response bodies. Success is
// HTTP 200, Content-Type application/json, exactly {"accepted":true}.
// No OS credential store or enrollment is asserted by these loopback tests.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"eguard-nac-agent/core"
)

const posturePath = "/v1/nac/posture"

type certFixture struct {
	roots          *x509.CertPool
	server, client tls.Certificate
}

func makeCerts(t *testing.T) certFixture { return makeCertsWithServerMismatch(t, false) }
func makeCertsWithServerMismatch(t *testing.T, mismatch bool) certFixture {
	t.Helper()
	now := time.Now()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, client bool) tls.Certificate {
		t.Helper()
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			tmpl.Subject = pkix.Name{CommonName: "synthetic-device"}
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			tmpl.DNSNames = []string{"localhost"}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			if mismatch {
				tmpl.DNSNames = []string{"other.test"}
				tmpl.IPAddresses = nil
			}
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		d, e := x509.CreateCertificate(rand.Reader, tmpl, caCert, p, priv)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{d, der}, PrivateKey: k}
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return certFixture{roots: roots, server: leaf(2, false), client: leaf(3, true)}
}
func tlsServer(t *testing.T, f certFixture, requireClient bool, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{f.server}, MinVersion: tls.VersionTLS12}
	if requireClient {
		s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		s.TLS.ClientCAs = f.roots
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func posture() core.Posture {
	return core.Posture{AgentType: "nac", Domain: core.DomainEvidence{PartOfDomain: core.Unknown, Match: core.Unknown}, AV: core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown}, Firewall: map[string]core.Evidence{}, Adapters: []core.Adapter{}, OS: "synthetic", ObservedAt: time.Now().UTC(), TTL: time.Minute}
}
func config(s *httptest.Server, f certFixture) Config {
	return Config{BaseURL: s.URL, RootCAs: f.roots, ClientCertificate: f.client, Timeout: time.Second}
}
func send(t *testing.T, cfg Config, ctx context.Context) error {
	t.Helper()
	c, e := NewClient(cfg)
	if e != nil {
		return e
	}
	return c.SendPosture(ctx, posture())
}
func accepted(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"accepted":true}`))
}

func TestTransportMTLSPostureRealHandshake(t *testing.T) {
	f := makeCerts(t)
	var seen atomic.Int32
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != posturePath || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.TLS == nil || len(r.TLS.PeerCertificates) < 1 || len(r.TLS.VerifiedChains) == 0 {
			t.Error("wrong fixed endpoint, JSON or client TLS identity")
			http.Error(w, "bad", 400)
			return
		}
		defer r.Body.Close()
		var p core.Posture
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.AgentType != "nac" || p.Domain.PartOfDomain != core.Unknown || p.OS != "synthetic" {
			t.Error("actual core posture not transmitted")
			http.Error(w, "bad", 400)
			return
		}
		seen.Add(1)
		accepted(w)
	})
	if err := send(t, config(s, f), context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen.Load() != 1 {
		t.Fatal("expected one authenticated request")
	}
}
func TestTransportRejectsUntrustedHostnameMissingCertAndPlainHTTP(t *testing.T) {
	f := makeCerts(t)
	var seen atomic.Int32
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) { seen.Add(1); accepted(w) })
	cases := map[string]func(*Config){
		"unknown CA":            func(c *Config) { c.RootCAs = x509.NewCertPool() },
		"no client certificate": func(c *Config) { c.ClientCertificate = tls.Certificate{} },
		"plaintext":             func(c *Config) { c.BaseURL = strings.Replace(c.BaseURL, "https:", "http:", 1) },
	}
	// Wrong-SAN server uses a trusted CA and accepts TCP on the same loopback host.
	wrongSAN := makeCertsWithServerMismatch(t, true)
	mismatchServer := tlsServer(t, wrongSAN, true, func(w http.ResponseWriter, r *http.Request) { seen.Add(1); accepted(w) })
	if err := send(t, config(mismatchServer, wrongSAN), context.Background()); err == nil {
		t.Fatal("hostname mismatch accepted")
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config(s, f)
			change(&cfg)
			if err := send(t, cfg, context.Background()); err == nil {
				t.Fatal("untrusted transport accepted")
			}
		})
	}
	if seen.Load() != 0 {
		t.Fatal("posture reached untrusted endpoint")
	}
}
func TestTransportRejectsMalformedConfiguration(t *testing.T) {
	f := makeCerts(t)
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid config sent request") })
	for name, raw := range map[string]string{"userinfo": "https://user:pass@" + strings.TrimPrefix(s.URL, "https://"), "query": s.URL + "?device=forged", "fragment": s.URL + "#other", "path": s.URL + "/arbitrary", "plaintext": "http://127.0.0.1:1"} {
		t.Run(name, func(t *testing.T) {
			cfg := config(s, f)
			cfg.BaseURL = raw
			if err := send(t, cfg, context.Background()); err == nil {
				t.Fatal("invalid URL accepted")
			}
		})
	}
}
func TestTransportRedirectDoesNotLeakPostureOrIdentity(t *testing.T) {
	f := makeCerts(t)
	var targetHits atomic.Int32
	target := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) { targetHits.Add(1); accepted(w) })
	source := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+posturePath, http.StatusTemporaryRedirect)
	})
	if err := send(t, config(source, f), context.Background()); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
	if targetHits.Load() != 0 {
		t.Fatal("posture or client credential sent to redirect target")
	}
}
func TestTransportTimeoutAndCancellation(t *testing.T) {
	f := makeCerts(t)
	release := make(chan struct{})
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	cfg := config(s, f)
	cfg.Timeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if err := send(t, cfg, ctx); err == nil {
		t.Fatal("timeout accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not bounded")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := send(t, config(s, f), canceled); err == nil {
		t.Fatal("canceled context accepted")
	}
}
func TestTransportResponseAndRequestLimitsAndSchema(t *testing.T) {
	f := makeCerts(t)
	for name, handler := range map[string]http.HandlerFunc{
		"non 2xx": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "denied", http.StatusForbidden) },
		"wrong content type": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`{"accepted":true}`))
		},
		"malformed JSON": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accepted":`))
		},
		"untrusted assignment": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accepted":true,"tenant_id":"forged","mode":"permanent"}`))
		},
		"negative acknowledgement": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accepted":false}`))
		},
		"large response": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", 256*1024)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := tlsServer(t, f, true, handler)
			if err := send(t, config(s, f), context.Background()); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	s := tlsServer(t, f, true, func(w http.ResponseWriter, r *http.Request) {
		t.Error("oversized posture was transmitted")
		accepted(w)
	})
	c, e := NewClient(config(s, f))
	if e != nil {
		t.Fatal(e)
	}
	p := posture()
	p.OS = strings.Repeat("x", 256*1024)
	if err := c.SendPosture(context.Background(), p); err == nil {
		t.Fatal("oversized request accepted")
	}
}
