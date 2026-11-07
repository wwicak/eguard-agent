// Package selfenroll redeems a single-use enrollment code: it sends the
// device's CSR to the pinned eGuard enrollment endpoint and returns the issued
// certificate with the signed bootstrap and activation. Nothing returned is
// trusted here: admission verifies the bootstrap against the compiled-in pin
// and the activation against the bootstrap's lifecycle keys.
package selfenroll

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Set at link time: -X eguard-nac-agent/selfenroll.ServerURL=https://host:port
// and -X eguard-nac-agent/selfenroll.ServerCAB64=<base64 DER>.
var (
	ServerURL   string
	ServerCAB64 string
)

var ErrCode = errors.New("enrollment code was rejected (invalid, already used, expired or revoked)")

const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Normalize accepts the code with or without dashes/spaces, any case.
func Normalize(code string) (string, error) {
	c := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	if len(c) != 10 {
		return "", errors.New("enrollment code must have 10 characters")
	}
	for _, r := range c {
		if !strings.ContainsRune(alphabet, r) {
			return "", errors.New("enrollment code contains an invalid character")
		}
	}
	return c, nil
}

// CleanHostname preserves the Windows ComputerName while limiting wire text.
func CleanHostname(name string) string {
	var b strings.Builder
	for _, c := range name {
		if b.Len() >= 63 {
			break
		}
		if c > 127 || !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			c = '-'
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}

type Result struct {
	CertificateDER []byte
	Bootstrap      []byte
	Activation     []byte
}

// Endpoint returns the compiled-in enrollment URL and CA pool.
func Endpoint() (string, *x509.CertPool, error) {
	u, err := url.Parse(ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		return "", nil, errors.New("installer has no enrollment server configured")
	}
	der, err := base64.StdEncoding.DecodeString(ServerCAB64)
	if err != nil {
		return "", nil, errors.New("installer has no enrollment CA configured")
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return "", nil, errors.New("installer has no enrollment CA configured")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ServerURL + "/v1/nac/enroll", pool, nil
}

// Redeem posts code+CSR to endpoint over TLS verified against roots only.
func Redeem(endpoint string, roots *x509.CertPool, code string, csrPEM []byte, hostname string, platform ...string) (Result, error) {
	var zero Result
	c, err := Normalize(code)
	if err != nil {
		return zero, err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	fields := map[string]string{"code": c, "csr_pem": string(csrPEM), "hostname": hostname}
	// Omit on Windows to preserve the existing wire format. Variadic for
	// source compatibility with stamped Windows installers.
	if len(platform) > 1 {
		return zero, errors.New("invalid enrollment platform")
	}
	if len(platform) == 1 && platform[0] != "" && platform[0] != "windows" {
		if platform[0] != "linux" && platform[0] != "darwin" {
			return zero, errors.New("invalid enrollment platform")
		}
		fields["platform"] = platform[0]
	}
	body, _ := json.Marshal(fields)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("cannot reach the eGuard enrollment server: %w", err)
	}
	defer resp.Body.Close()
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	switch resp.StatusCode {
	case 200:
	case 403:
		return zero, ErrCode
	default:
		return zero, fmt.Errorf("enrollment server returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Cert string `json:"certificate_pem"`
		Boot string `json:"bootstrap"`
		Act  string `json:"activation"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Boot == "" || out.Act == "" {
		return zero, errors.New("enrollment server response is malformed")
	}
	blk, _ := pem.Decode([]byte(out.Cert))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return zero, errors.New("enrollment server response has no certificate")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		return zero, errors.New("enrollment server certificate is malformed")
	}
	return Result{CertificateDER: blk.Bytes, Bootstrap: []byte(out.Boot), Activation: []byte(out.Act)}, nil
}
