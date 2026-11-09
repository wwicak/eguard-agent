//go:build windows

package cngcred

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"unsafe"
)

// Resolve finds exactly one leaf DER fingerprint in LocalMachine\\MY. The returned
// certificate's PrivateKey is a crypto.Signer backed by the CNG key handle;
// caller must Close the returned resource after all TLS use finishes.
func Resolve(fingerprint [32]byte) (tls.Certificate, io.Closer, error) {
	var empty tls.Certificate
	name, e := windows.UTF16PtrFromString("MY")
	if e != nil {
		return empty, nil, e
	}
	store, e := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(name)))
	if e != nil {
		return empty, nil, e
	}
	r := &resource{store: store}
	fail := func(e error) (tls.Certificate, io.Closer, error) { _ = r.Close(); return empty, nil, e }
	var prev *windows.CertContext
	count := 0
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		// The enumeration API frees prev even when returning nil or an error.
		prev = ctx
		if ctx == nil {
			if err != nil && !errors.Is(err, cryptENotFound) {
				return fail(err)
			}
			break
		}
		if ctx.Length == 0 || ctx.Length > 1<<20 {
			continue
		}
		der := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
		sum := sha256.Sum256(der)
		if sum == fingerprint {
			count++
			if count == 1 {
				r.cert = windows.CertDuplicateCertificateContext(ctx)
				if r.cert == nil {
					return fail(errors.New("cannot retain certificate context"))
				}
			}
		}
	}
	if count != 1 {
		return fail(errors.New("machine certificate missing or ambiguous"))
	}
	der := append([]byte(nil), unsafe.Slice(r.cert.EncodedCert, int(r.cert.Length))...)
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		return fail(e)
	}
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return fail(errors.New("unsupported ECDSA curve"))
		}
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return fail(errors.New("RSA key too short"))
		}
	default:
		return fail(errors.New("unsupported certificate key"))
	}
	r.pub = leaf.PublicKey
	var spec uint32
	e = windows.CryptAcquireCertificatePrivateKey(r.cert, windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_COMPARE_KEY_FLAG, nil, &r.key, &spec, &r.callerFree)
	if e != nil {
		return fail(e)
	}
	if spec != windows.CERT_NCRYPT_KEY_SPEC || r.key == 0 {
		return fail(errors.New("not an NCRYPT private key"))
	}
	// Export policy 0: no private-key export permitted. Some providers do not
	// implement this property; these cannot establish non-exportability and fail closed.
	exportable, e := r.exportable()
	if e != nil || exportable {
		return fail(errors.New("CNG key export policy unavailable or exportable"))
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: r, Leaf: leaf}, r, nil
}

func (r *resource) exportable() (bool, error) {
	prop, _ := windows.UTF16PtrFromString("Export Policy")
	var value uint32
	var size uint32
	v, _, _ := getProperty.Call(uintptr(r.key), uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&value)), 4, uintptr(unsafe.Pointer(&size)), 0)
	if e := statusError(v); e != nil {
		return false, e
	}
	if size != 4 {
		return false, errors.New("invalid export policy")
	}
	// NCRYPT_ALLOW_EXPORT_FLAG 0x1, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG 0x2,
	// NCRYPT_ALLOW_ARCHIVING_FLAG 0x4, NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG 0x8.
	return value&0xf != 0, nil
}
