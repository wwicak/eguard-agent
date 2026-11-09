//go:build windows

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"eguard-nac-agent/cngcred"
	"eguard-nac-agent/provision"
	"eguard-nac-agent/selfenroll"
	"eguard-nac-agent/setupflow"
	"golang.org/x/sys/windows"
)

// Fixed request template: LocalMachine CNG key, non-exportable ECDSA P-256,
// client-auth only. The subject is replaced by the server with the enrolled
// device name; the key never leaves the machine.
const csrINF = `[NewRequest]
Subject = "CN=eguard-nac-enroll"
KeyAlgorithm = ECDSA_P256
KeyLength = 256
MachineKeySet = TRUE
Exportable = FALSE
ProviderName = "Microsoft Software Key Storage Provider"
KeyUsage = 0x80
RequestType = PKCS10
HashAlgorithm = SHA256
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
`

func certreq(args ...string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "certreq.exe")
	out, err := exec.Command(exe, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("certreq %s: %v: %s", args[0], err, out)
	}
	return nil
}

func certutil(args ...string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "certutil.exe")
	out, err := exec.Command(exe, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil %s: %v: %s", args[0], err, out)
	}
	return nil
}

// placeMachineCert binds the issued certificate to the pending machine key in
// LocalMachine\MY. The eGuard CA is pinned by the agent itself, so the device
// does not need to trust it in Windows: when "certreq -accept" refuses an
// untrusted chain, the certificate is added to MY and linked to its existing
// private key with "certutil -repairstore". The Windows trust store is never
// modified.
func placeMachineCert(cer string, fp [32]byte) error {
	if err := certreq("-accept", "-q", "-machine", cer); err == nil {
		return nil
	}
	sha1 := sha1Thumbprint(cer)
	if sha1 == "" {
		return errors.New("issued certificate is unreadable")
	}
	if err := certutil("-f", "-addstore", "My", cer); err != nil {
		return err
	}
	if err := certutil("-repairstore", "My", sha1); err != nil {
		_ = cngcred.Delete(fp)
		return fmt.Errorf("could not link the certificate to the device key: %w", err)
	}
	// Drop the pending request entry left by certreq -new (the key stays bound to MY).
	_ = certutil("-delstore", "Request", sha1Pending())
	return nil
}

// installWithCode: create the machine key + CSR, redeem the code, install the
// certificate, then run the normal verified install. Any failure removes the
// certificate/key it created.
func installWithCode(service, code string) error {
	if _, err := selfenroll.Normalize(code); err != nil {
		return err
	}
	// Refuse before the single-use code is spent when this device cannot be
	// installed (agent present, removal pending a restart, no rights).
	if err := installBlocked(); err != nil {
		return err
	}
	endpoint, roots, err := selfenroll.Endpoint()
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "eguard-nac-enroll-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	inf, csr, cer := filepath.Join(work, "req.inf"), filepath.Join(work, "req.csr"), filepath.Join(work, "machine.cer")
	if err := os.WriteFile(inf, []byte(csrINF), 0o600); err != nil {
		return err
	}
	if err := certreq("-new", "-q", "-machine", inf, csr); err != nil {
		return err
	}
	csrPEM, err := os.ReadFile(csr)
	if err != nil {
		return err
	}
	hostname, err := windows.ComputerName()
	if err != nil {
		return err
	}
	res, err := selfenroll.Redeem(endpoint, roots, code, csrPEM, selfenroll.CleanHostname(hostname))
	if err != nil {
		// The pending request key stays in the REQUEST store only; certreq
		// removes it when superseded. No agent state was written.
		return err
	}
	fp := sha256.Sum256(res.CertificateDER)
	if err := os.WriteFile(cer, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.CertificateDER}), 0o600); err != nil {
		return err
	}
	if err := placeMachineCert(cer, fp); err != nil {
		return err
	}
	boot, act := filepath.Join(work, "bootstrap.json"), filepath.Join(work, "activation.json")
	if err := errors.Join(os.WriteFile(boot, res.Bootstrap, 0o600), os.WriteFile(act, res.Activation, 0o600)); err != nil {
		_ = cngcred.Delete(fp)
		return err
	}
	if err := setupflow.Install(setupflow.Windows{SourceBinary: service, Bootstrap: boot, Activation: act}); err != nil {
		_ = cngcred.Delete(fp)
		return err
	}
	return nil
}

func sha1Thumbprint(cer string) string {
	raw, err := os.ReadFile(cer)
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return ""
	}
	h := sha1.Sum(blk.Bytes)
	return hex.EncodeToString(h[:])
}

// sha1Pending names the pending request by its fixed subject.
func sha1Pending() string { return "eguard-nac-enroll" }

func installBlocked() error {
	if !elevated() {
		return errors.New("administrator rights are required")
	}
	if _, err := os.Lstat(provision.Root); err == nil {
		return errors.New("eGuard NAC is already installed on this device; uninstall it first (your enrollment code was not used)")
	}
	return setupflow.CheckExisting()
}
