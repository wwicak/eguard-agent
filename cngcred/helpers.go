// Package cngcred resolves an exact machine certificate fingerprint to a CNG-backed TLS signer.
package cngcred

import (
	"crypto"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"math/big"
)

// matchDER returns -1 for absent, -2 for ambiguous, or the unique index.
func matchDER(der [][]byte, fingerprint [32]byte) int {
	index := -1
	for i, blob := range der {
		sum := sha256.Sum256(blob)
		if subtle.ConstantTimeCompare(sum[:], fingerprint[:]) == 1 {
			if index >= 0 {
				return -2
			}
			index = i
		}
	}
	return index
}
func rawECDSAToDER(raw []byte, width int) ([]byte, error) {
	if width <= 0 || len(raw) != width*2 {
		return nil, errors.New("invalid CNG ECDSA signature size")
	}
	r := new(big.Int).SetBytes(raw[:width])
	s := new(big.Int).SetBytes(raw[width:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, errors.New("zero ECDSA scalar")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
func hashAlgorithm(hash crypto.Hash, size int) (string, error) {
	if !hash.Available() || size != hash.Size() {
		return "", errors.New("invalid digest size or hash")
	}
	switch hash {
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	}
	return "", errors.New("unsupported CNG hash")
}
