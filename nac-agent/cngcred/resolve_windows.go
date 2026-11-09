//go:build windows

package cngcred

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ncrypt = windows.NewLazySystemDLL("ncrypt.dll")
var signHash = ncrypt.NewProc("NCryptSignHash")
var freeObject = ncrypt.NewProc("NCryptFreeObject")
var getProperty = ncrypt.NewProc("NCryptGetProperty")

const (
	ncryptPadPKCS1 = 0x2
	ncryptPadPSS   = 0x8
	cryptENotFound = syscall.Errno(0x80092004)
)

type pkcs1Padding struct{ algorithm *uint16 }
type pssPadding struct {
	algorithm  *uint16
	saltLength uint32
}

type resource struct {
	mu         sync.Mutex
	key        windows.Handle
	callerFree bool
	cert       *windows.CertContext
	store      windows.Handle
	pub        crypto.PublicKey
	closed     bool
}

var _ crypto.Signer = (*resource)(nil)
var _ io.Closer = (*resource)(nil)

func (r *resource) Public() crypto.PublicKey { return r.pub }
func statusError(code uintptr) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("CNG status 0x%08x", uint32(code))
}
func (r *resource) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.key != 0 && r.callerFree {
		v, _, _ := freeObject.Call(uintptr(r.key))
		err = errors.Join(err, statusError(v))
	}
	r.key = 0
	if r.cert != nil {
		err = errors.Join(err, windows.CertFreeCertificateContext(r.cert))
		r.cert = nil
	}
	if r.store != 0 {
		err = errors.Join(err, windows.CertCloseStore(r.store, 0))
		r.store = 0
	}
	return err
}
func (r *resource) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.key == 0 {
		return nil, errors.New("CNG signer closed")
	}
	if opts == nil {
		return nil, errors.New("missing signer options")
	}
	name, e := hashAlgorithm(opts.HashFunc(), len(digest))
	if e != nil {
		return nil, e
	}
	alg, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return nil, e
	}
	var info unsafe.Pointer
	var flags uintptr
	switch pub := r.pub.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize != 256 && pub.Curve.Params().BitSize != 384 {
			return nil, errors.New("unsupported ECDSA curve")
		}
		if (pub.Curve.Params().BitSize == 256 && opts.HashFunc() != crypto.SHA256) || (pub.Curve.Params().BitSize == 384 && opts.HashFunc() != crypto.SHA384) {
			return nil, errors.New("ECDSA hash mismatch")
		}
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			salt := opts.HashFunc().Size()
			if pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != rsa.PSSSaltLengthAuto && pss.SaltLength != salt {
				return nil, errors.New("unsupported PSS salt length")
			}
			padding := pssPadding{alg, uint32(salt)}
			info = unsafe.Pointer(&padding)
			flags = ncryptPadPSS
		} else {
			padding := pkcs1Padding{alg}
			info = unsafe.Pointer(&padding)
			flags = ncryptPadPKCS1
		}
	default:
		return nil, errors.New("unsupported public key")
	}
	// NCryptSignHash may report a variable length signature; retry on buffer-too-small.
	var size uint32
	v, _, _ := signHash.Call(uintptr(r.key), uintptr(info), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0, uintptr(unsafe.Pointer(&size)), flags)
	if e = statusError(v); e != nil {
		return nil, e
	}
	if size == 0 || size > 16384 {
		return nil, errors.New("invalid CNG signature size")
	}
	out := make([]byte, size)
	v, _, _ = signHash.Call(uintptr(r.key), uintptr(info), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&size)), flags)
	if e = statusError(v); e != nil {
		return nil, e
	}
	if size == 0 || int(size) > len(out) {
		return nil, errors.New("invalid CNG signature length")
	}
	out = out[:size]
	if pub, ok := r.pub.(*ecdsa.PublicKey); ok {
		width := (pub.Curve.Params().BitSize + 7) / 8
		der, e := rawECDSAToDER(out, width)
		if e != nil {
			return nil, e
		}
		var sig struct{ R, S *big.Int }
		if _, e = asn1.Unmarshal(der, &sig); e != nil || !ecdsa.Verify(pub, digest, sig.R, sig.S) {
			return nil, errors.New("invalid CNG ECDSA signature")
		}
		return der, nil
	}
	return out, nil
}
