//go:build windows

package cngcred

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// Operator provisions a non-exportable LocalMachine\\MY key and its certificate
// separately (e.g. New-SelfSignedCertificate); this test never installs one.
func TestMachineCredentialIntegration(t *testing.T) {
	if os.Getenv("EGUARD_NAC_CNG_ITEST") != "1" {
		t.Skip("opt-in Windows machine credential test")
	}
	text := os.Getenv("EGUARD_NAC_CNG_FP")
	raw, e := hex.DecodeString(text)
	if e != nil || len(raw) != 32 {
		t.Fatal("EGUARD_NAC_CNG_FP must be 64 hexadecimal characters")
	}
	var fp [32]byte
	copy(fp[:], raw)
	cert, closer, e := Resolve(fp)
	if e != nil {
		t.Fatal(e)
	}
	defer closer.Close()
	if sha256.Sum256(cert.Certificate[0]) != fp {
		t.Fatal("wrong leaf DER")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("no signer")
	}
	digest := sha256.Sum256([]byte("eguard nac CNG integration"))
	signature, e := signer.Sign(nil, digest[:], crypto.SHA256)
	if e != nil {
		t.Fatal(e)
	}
	switch pub := cert.Leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			t.Fatal("ECDSA verify failed")
		}
	case *rsa.PublicKey:
		if e = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); e != nil {
			t.Fatal(e)
		}
		pss, e := signer.Sign(nil, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		if e != nil {
			t.Fatal(e)
		}
		if e = rsa.VerifyPSS(pub, crypto.SHA256, digest[:], pss, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); e != nil {
			t.Fatal(e)
		}
	default:
		t.Fatal("unsupported public key")
	}
	if exported, e := signer.(*resource).exportable(); e != nil || exported {
		t.Fatalf("export policy unavailable or exportable: %v", e)
	}
	if e = closer.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = signer.Sign(nil, digest[:], crypto.SHA256); e == nil {
		t.Fatal("sign after close succeeded")
	}
}
