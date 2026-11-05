// Package transport provides bounded, origin-fixed NAC posture delivery.
package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"eguard-nac-agent/core"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"
)

type Config struct {
	// Now adds trusted-time verification without disabling standard TLS checks.
	// Nil preserves the standalone transport's system-clock behavior.
	Now               func() (time.Time, error)
	BaseURL           string
	RootCAs           *x509.CertPool
	ClientCertificate tls.Certificate
	Timeout           time.Duration
	// OnLifecycle receives an optional signed lifecycle envelope (e.g. a remote
	// uninstall authorization) piggy-backed on the acknowledgement. Transport
	// does not trust it; the caller verifies the lifecycle signature.
	OnLifecycle func([]byte)
}
type Client struct {
	endpoint    string
	inventory   string
	onLifecycle func([]byte)
	http        *http.Client
}

var errTransport = errors.New("NAC transport rejected request or response")

func NewClient(c Config) (*Client, error) {
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || c.RootCAs == nil || len(c.ClientCertificate.Certificate) == 0 || c.ClientCertificate.PrivateKey == nil || c.Timeout <= 0 || c.Timeout > time.Minute {
		return nil, errTransport
	}
	cert := c.ClientCertificate
	cert.Certificate = make([][]byte, len(c.ClientCertificate.Certificate))
	for i, b := range c.ClientCertificate.Certificate {
		cert.Certificate[i] = append([]byte(nil), b...)
	}
	t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs.Clone(), Certificates: []tls.Certificate{cert}}, TLSHandshakeTimeout: c.Timeout, ResponseHeaderTimeout: c.Timeout, MaxResponseHeaderBytes: 16384, DisableCompression: true, MaxConnsPerHost: 2}
	if c.Now != nil {
		// A fresh TLS handshake for every submission ensures trusted-time
		// verification occurs before its HTTP bytes, even after long idle gaps.
		// Session caching is not enabled; do not enable HTTP/2 pooling here.
		t.DisableKeepAlives = true
		roots := c.RootCAs.Clone()
		t.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
			now, err := c.Now()
			if err != nil || now.IsZero() || len(state.PeerCertificates) == 0 {
				return errTransport
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err = state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: u.Hostname(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if err != nil {
				return errTransport
			}
			return nil
		}
	}
	return &Client{onLifecycle: c.OnLifecycle, endpoint: u.String() + "/v1/nac/posture", inventory: u.String() + "/v1/nac/inventory", http: &http.Client{Transport: t, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errTransport }}}, nil
}

// CloseIdleConnections releases pooled connections after the owning runner joins.
// It does not cancel in-flight sends or permanently disable the client.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

// Submission is a one-shot preparation reusable for explicit retries. No mutable
// body or key is exposed. Its integrity seal rejects zero or corrupted values.
type Submission struct {
	body string
	key  string
	seal [32]byte
}

func sealSubmission(key, body string) [32]byte { return sha256.Sum256([]byte(key + body)) }

// PreparePosture serializes before returning: later map/slice mutations cannot alter
// the immutable bytes. A fresh invocation produces a fresh 128-bit random ID.
func PreparePosture(p core.Posture) (Submission, error) {
	body, e := json.Marshal(p)
	if e != nil || len(body) == 0 || len(body) > 64*1024 {
		return Submission{}, errTransport
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return Submission{}, errTransport
	}
	s := Submission{body: string(body), key: hex.EncodeToString(id[:])}
	s.seal = sealSubmission(s.key, s.body)
	return s, nil
}

// SendPosture is convenience for a NEW submission per invocation, never a retry
// of a preceding invocation. Call SendSubmission with the same value to retry.
func (c *Client) SendPosture(ctx context.Context, p core.Posture) error {
	s, e := PreparePosture(p)
	if e != nil {
		return e
	}
	return c.SendSubmission(ctx, s)
}

// SendSubmission sends exactly one request; no automatic retries or disk queue.
func (c *Client) SendSubmission(ctx context.Context, s Submission) error {
	if c == nil || c.http == nil || len(s.key) != 32 || len(s.body) == 0 || len(s.body) > 64*1024 || s.seal != sealSubmission(s.key, s.body) {
		return errTransport
	}
	id, e := hex.DecodeString(s.key)
	if e != nil || len(id) != 16 || hex.EncodeToString(id) != s.key {
		return errTransport
	}
	// A separate reader per call prevents concurrent sends from sharing mutable state.
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader([]byte(s.body)))
	if e != nil {
		return errTransport
	}
	req.Header.Set("Idempotency-Key", s.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return errTransport
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errTransport
	}
	media, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		return errTransport
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || len(raw) > 4096 {
		return errTransport
	}
	// Token parsing rejects duplicates, extra fields and trailing JSON.
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return errTransport
	}
	tok, e = d.Token()
	if e != nil || tok != "accepted" {
		return errTransport
	}
	tok, e = d.Token()
	if e != nil || tok != true {
		return errTransport
	}
	tok, e = d.Token()
	var lifecycle []byte
	if e == nil && tok == "lifecycle" {
		// Exactly one optional field, after "accepted", holding base64url text.
		tok, e = d.Token()
		str, isStr := tok.(string)
		if e != nil || !isStr || str == "" {
			return errTransport
		}
		if lifecycle, e = base64.RawURLEncoding.DecodeString(str); e != nil || !json.Valid(lifecycle) {
			return errTransport
		}
		tok, e = d.Token()
	}
	if e != nil || tok != json.Delim('}') {
		return errTransport
	}
	if _, e = d.Token(); e != io.EOF {
		return errTransport
	}
	if lifecycle != nil && c.onLifecycle != nil {
		c.onLifecycle(lifecycle)
	}
	return nil
}

// SendInventory sends the optional inventory once (no retries, no queue). The
// acknowledgement must be exactly {"accepted":true}.
func (c *Client) SendInventory(ctx context.Context, inv core.Inventory) error {
	if c == nil || c.http == nil {
		return errTransport
	}
	body, e := json.Marshal(inv)
	if e != nil || len(body) == 0 || len(body) > core.MaxInventoryBytes {
		return errTransport
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.inventory, bytes.NewReader(body))
	if e != nil {
		return errTransport
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return errTransport
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 257))
	if e != nil || resp.StatusCode != http.StatusOK || len(raw) > 256 || !bytes.Equal(bytes.TrimSpace(raw), []byte(`{"accepted":true}`)) {
		return errTransport
	}
	return nil
}
