//go:build linux || darwin

// Package unixagent supplies fixed-resource Unix NAC integration. It never
// executes a shell or accepts executable names from the server or CLI.
package unixagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func createKey(root string) ([]byte, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	der, e := x509.MarshalECPrivateKey(k)
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(root, "machine-key.pem"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	_, e = f.Write(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	e = errors.Join(e, f.Sync(), f.Close())
	if e != nil {
		return nil, e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "eguard-nac-enroll"}}, k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}
func ResolveCredential(root string) func([32]byte) (tls.Certificate, io.Closer, error) {
	return func(fp [32]byte) (tls.Certificate, io.Closer, error) {
		var zero tls.Certificate
		for _, name := range []string{"machine-key.pem", "machine-cert.pem"} {
			i, e := os.Lstat(filepath.Join(root, name))
			if e != nil {
				return zero, nil, e
			}
			if !i.Mode().IsRegular() || i.Mode().Perm() != 0600 {
				return zero, nil, errors.New("unsafe machine credential permissions")
			}
		}
		c, e := tls.LoadX509KeyPair(filepath.Join(root, "machine-cert.pem"), filepath.Join(root, "machine-key.pem"))
		if e != nil {
			return zero, nil, e
		}
		if len(c.Certificate) != 1 || sha256.Sum256(c.Certificate[0]) != fp {
			return zero, nil, errors.New("machine certificate fingerprint mismatch")
		}
		return c, nopCloser{}, nil
	}
}
