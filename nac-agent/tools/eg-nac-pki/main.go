// eg-nac-pki: generates the per-site NAC Agent trust material ON the eGuard
// server. Private keys are written 0600 and never printed.
//
//	eg-nac-pki init <dir> <cn-suffix> <ip-or-dns>[,<ip-or-dns>...]
//	    ca.pem/ca.key        client CA (signs machine certs at enrollment), 10y
//	    server.pem/.key      gateway TLS cert for :8793/:8795, 2y, SAN from args
//	    boot.key/boot.pub    ed25519 bootstrap signer (pub is pinned in installer)
//	    lifecycle.key/.pub   ed25519 lifecycle signer (remote uninstall/expiry)
//	eg-nac-pki renew-server <dir> <ip-or-dns>[,...]   re-issue server cert only
//
// Refuses to overwrite existing keys.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "eg-nac-pki:", err)
		os.Exit(1)
	}
}

func create(path string, data []byte, mode os.FileMode) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	die(err)
	_, err = f.Write(data)
	die(err)
	die(f.Close())
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	die(err)
	return n.Add(n, big.NewInt(1))
}

func sans(list string) ([]net.IP, []string) {
	var ips []net.IP
	var dns []string
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, s)
		}
	}
	if len(ips)+len(dns) == 0 {
		die(errors.New("at least one IP/DNS SAN required"))
	}
	return ips, dns
}

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey) {
	cb, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	die(err)
	kb, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	die(err)
	c, _ := pem.Decode(cb)
	k, _ := pem.Decode(kb)
	if c == nil || k == nil {
		die(errors.New("ca.pem/ca.key not PEM"))
	}
	ca, err := x509.ParseCertificate(c.Bytes)
	die(err)
	key, err := x509.ParseECPrivateKey(k.Bytes)
	die(err)
	return ca, key
}

func issueServer(dir, list string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) {
	ips, dns := sans(list)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	die(err)
	now := time.Now()
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "eguard-nac-gateway"},
		IPAddresses: ips, DNSNames: dns, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, t, ca, &key.PublicKey, caKey)
	die(err)
	kb, err := x509.MarshalECPrivateKey(key)
	die(err)
	create(filepath.Join(dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	create(filepath.Join(dir, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

func edPair(dir, name string) string {
	pub, k, err := ed25519.GenerateKey(rand.Reader)
	die(err)
	create(filepath.Join(dir, name+".key"), []byte(hex.EncodeToString(k)), 0o600)
	create(filepath.Join(dir, name+".pub"), []byte(hex.EncodeToString(pub)), 0o644)
	return hex.EncodeToString(pub)
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: eg-nac-pki init <dir> <cn-suffix> <san,...> | renew-server <dir> <san,...>")
		os.Exit(2)
	}
	dir := os.Args[2]
	switch os.Args[1] {
	case "init":
		if len(os.Args) < 5 {
			die(errors.New("init needs <dir> <cn-suffix> <san,...>"))
		}
		die(os.MkdirAll(dir, 0o700))
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		die(err)
		now := time.Now()
		t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "eGuard NAC Agent CA " + os.Args[3]},
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0)}
		der, err := x509.CreateCertificate(rand.Reader, t, t, &caKey.PublicKey, caKey)
		die(err)
		kb, err := x509.MarshalECPrivateKey(caKey)
		die(err)
		create(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
		create(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
		ca, _ := x509.ParseCertificate(der)
		issueServer(dir, os.Args[4], ca, caKey)
		fmt.Println("BOOT_PIN=" + edPair(dir, "boot"))
		edPair(dir, "lifecycle")
		fmt.Println("PKI_OK " + dir)
	case "renew-server":
		ca, caKey := loadCA(dir)
		for _, n := range []string{"server.pem", "server.key"} {
			p := filepath.Join(dir, n)
			if _, err := os.Stat(p); err == nil {
				die(os.Rename(p, p+".old-"+time.Now().UTC().Format("20060102T150405Z")))
			}
		}
		issueServer(dir, os.Args[3], ca, caKey)
		fmt.Println("SERVER_RENEWED")
	default:
		die(errors.New("unknown command"))
	}
}
