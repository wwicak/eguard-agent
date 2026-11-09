package main

// e2e client: code -> CSR enroll on :18795 -> posture with issued cert on :18793.
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	core "eguard-nac-agent/core"
)

func main() {
	dir, code := os.Args[1], os.Args[2]
	caPEM, _ := os.ReadFile(dir + "/tls/ca.pem")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "e2e"}}, key)
	body, _ := json.Marshal(map[string]string{"code": code, "csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "hostname": "BSSB-E2E-PC"})
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	r, err := c.Post("https://127.0.0.1:18793/v1/nac/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	b, _ := io.ReadAll(r.Body)
	fmt.Println("ENROLL", r.StatusCode)
	var out struct {
		Cert string `json:"certificate_pem"`
		Boot string `json:"bootstrap"`
	}
	_ = json.Unmarshal(b, &out)
	var env struct {
		P []byte `json:"payload_b64"`
	}
	_ = json.Unmarshal([]byte(out.Boot), &env)
	var boot map[string]any
	_ = json.Unmarshal(env.P, &boot)
	fmt.Println("BOOT origin", boot["https_origin"], "binding", boot["binding"])
	blk, _ := pem.Decode([]byte(out.Cert))
	cert, _ := x509.ParseCertificate(blk.Bytes)
	fmt.Println("CERT CN", cert.Subject.CommonName, "issuer", cert.Issuer.CommonName, "verify", func() error {
		_, e := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return e
	}())
	pair := tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key}
	mc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}}}}
	p := core.Posture{Hostname: "BSSB-E2E-PC", AgentType: "nac", OS: "windows-10.0.19045/amd64", ObservedAt: time.Now().UTC().Add(-time.Second), TTL: 5 * time.Minute,
		Domain:   core.DomainEvidence{PartOfDomain: core.No, Match: core.Unknown, Source: "NetGetJoinInformation"},
		AV:       core.AVEvidence{Installed: core.Unknown, Running: core.Unknown, Updated: core.Unknown, Source: "e2e"},
		Adapters: []core.Adapter{{Primary: true, Name: "Ethernet", MAC: "02:00:5e:00:e2:e2", Addresses: []string{"10.255.255.2/24"}, Kind: "physical", KindSource: "x", ActiveRoute: true, RouteStatus: core.Yes, RouteSource: "x"}}}
	pb, _ := json.Marshal(p)
	rq, _ := http.NewRequest("POST", "https://127.0.0.1:18793/v1/nac/posture", bytes.NewReader(pb))
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Idempotency-Key", fmt.Sprintf("e2e-%d", time.Now().UnixNano()))
	r2, err := mc.Do(rq)
	if err != nil {
		panic(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	fmt.Println("POSTURE", r2.StatusCode, string(b2)[:min(len(b2), 160)])
}
