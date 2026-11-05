//go:build windows

package cngcred

import (
	"crypto/sha256"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var deleteKey = ncrypt.NewProc("NCryptDeleteKey")

// ErrNotFound reports that no certificate with the fingerprint exists (idempotent cleanup).
var ErrNotFound = errors.New("machine certificate not found")

// Delete removes exactly the LocalMachine\MY certificate whose leaf DER SHA-256
// equals fingerprint, and its CNG private key. Absent → ErrNotFound. Ambiguous →
// refused (nothing deleted). Used only by official NAC cleanup.
func Delete(fingerprint [32]byte) error {
	name, e := windows.UTF16PtrFromString("MY")
	if e != nil {
		return e
	}
	store, e := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(name)))
	if e != nil {
		return e
	}
	defer windows.CertCloseStore(store, 0)
	var prev, match *windows.CertContext
	count := 0
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		prev = ctx
		if ctx == nil {
			if err != nil && !errors.Is(err, cryptENotFound) {
				if match != nil {
					windows.CertFreeCertificateContext(match)
				}
				return err
			}
			break
		}
		if ctx.Length == 0 || ctx.Length > 1<<20 {
			continue
		}
		if sha256.Sum256(unsafe.Slice(ctx.EncodedCert, int(ctx.Length))) == fingerprint {
			count++
			if count == 1 {
				match = windows.CertDuplicateCertificateContext(ctx)
			}
		}
	}
	if count == 0 {
		return ErrNotFound
	}
	if count != 1 {
		windows.CertFreeCertificateContext(match)
		return errors.New("machine certificate ambiguous; refusing deletion")
	}
	// Delete the CNG key first (needs the cert context to locate it).
	var key windows.Handle
	var spec uint32
	var callerFree bool
	keyErr := windows.CryptAcquireCertificatePrivateKey(match, windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG, nil, &key, &spec, &callerFree)
	if keyErr == nil && spec == windows.CERT_NCRYPT_KEY_SPEC && key != 0 {
		// NCryptDeleteKey frees the handle on success.
		v, _, _ := deleteKey.Call(uintptr(key), 0)
		if keyErr = statusError(v); keyErr != nil && callerFree {
			freeObject.Call(uintptr(key))
		}
	}
	// CertDeleteCertificateFromStore always frees the context it is given.
	certErr := windows.CertDeleteCertificateFromStore(match)
	return errors.Join(keyErr, certErr)
}
