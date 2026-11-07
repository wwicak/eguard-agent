package selfenroll

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Identity contains public enrollment trust material, never the enrollment code.
type Identity struct {
	Version      int    `json:"version"`
	CADERB64     string `json:"ca_der_b64"`
	BootstrapPin string `json:"bootstrap_pin"`
}

func ValidateFingerprint(fp string) error {
	b, e := hex.DecodeString(fp)
	if e != nil || len(b) != 32 || fp != strings.ToLower(fp) {
		return errors.New("fingerprint must be 64 lowercase hexadecimal characters")
	}
	return nil
}

func ValidateServer(host string) error {
	h, p, e := net.SplitHostPort(host)
	n, pe := strconv.Atoi(p)
	if e != nil || pe != nil || n < 1 || n > 65535 || h == "" || strings.ContainsAny(h, "/@?#%\\ \t\r\n") {
		return errors.New("server must be HOST:PORT without a URL path or credentials")
	}
	for _, r := range h {
		if r < 33 || r > 126 {
			return errors.New("invalid server hostname")
		}
	}
	u, e := url.Parse("https://" + host)
	if e != nil || u.Host != host || u.User != nil || u.Path != "" {
		return errors.New("invalid server address")
	}
	return nil
}

func (id Identity) Material() ([]byte, []byte, error) {
	der, e := base64.StdEncoding.Strict().DecodeString(id.CADERB64)
	if e != nil || len(der) > 64<<10 || id.Version != 1 {
		return nil, nil, errors.New("invalid enrollment identity")
	}
	if _, e = x509.ParseCertificate(der); e != nil {
		return nil, nil, errors.New("invalid enrollment CA")
	}
	if ValidateFingerprint(id.BootstrapPin) != nil || id.BootstrapPin == strings.Repeat("0", 64) {
		return nil, nil, errors.New("invalid bootstrap public key")
	}
	pin, _ := hex.DecodeString(id.BootstrapPin)
	return der, pin, nil
}

func (id Identity) Fingerprint() (string, error) {
	der, pin, e := id.Material()
	if e != nil {
		return "", e
	}
	h := sha256.New()
	h.Write([]byte("eguard-nac-identity/v1\x00"))
	h.Write(der)
	h.Write(pin)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FetchIdentity is the ONLY connection permitted to bypass TLS authentication.
// No code, CSR, cookie, proxy or redirect is used. The operator fingerprint
// authenticates the returned CA and bootstrap key before any redemption.
func FetchIdentity(ctx context.Context, host, fp string) (Identity, error) {
	var zero Identity
	if e := ValidateServer(host); e != nil {
		return zero, e
	}
	if e := ValidateFingerprint(fp); e != nil {
		return zero, e
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, MaxResponseHeaderBytes: 8192} // authenticated below, not general TOFU
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/v1/nac/identity", nil)
	if e != nil {
		return zero, e
	}
	res, e := c.Do(req)
	if e != nil {
		return zero, e
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return zero, errors.New("enrollment identity request failed")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 96<<10))
	if e != nil || len(raw) >= 96<<10 {
		return zero, errors.New("enrollment identity exceeds limit")
	}
	var id Identity
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if e = d.Decode(&id); e != nil {
		return zero, errors.New("invalid enrollment identity response")
	}
	if d.Decode(new(any)) != io.EOF {
		return zero, errors.New("invalid trailing identity data")
	}
	got, e := id.Fingerprint()
	if e != nil {
		return zero, e
	}
	if got != fp {
		return zero, errors.New("enrollment identity fingerprint mismatch; enrollment code was not sent")
	}
	return id, nil
}

func (id Identity) Roots() (*x509.CertPool, error) {
	der, _, e := id.Material()
	if e != nil {
		return nil, e
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, e
	}
	p := x509.NewCertPool()
	p.AddCert(ca)
	return p, nil
}
