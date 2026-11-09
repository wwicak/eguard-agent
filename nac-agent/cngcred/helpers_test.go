package cngcred

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestMatchDER(t *testing.T) {
	a := []byte{1, 2}
	b := []byte{3}
	fp := sha256.Sum256(a)
	for _, tt := range []struct {
		list [][]byte
		want int
	}{{[][]byte{b, a}, 1}, {[][]byte{b}, -1}, {[][]byte{a, a}, -2}} {
		if got := matchDER(tt.list, fp); got != tt.want {
			t.Fatalf("match=%d want %d", got, tt.want)
		}
	}
}
func TestRawECDSA(t *testing.T) {
	raw := []byte{0, 0x80, 0, 0x81}
	der, e := rawECDSAToDER(raw, 2)
	if e != nil {
		t.Fatal(e)
	}
	var rs struct{ R, S *big.Int }
	if _, e = asn1.Unmarshal(der, &rs); e != nil || rs.R.Int64() != 128 || rs.S.Int64() != 129 {
		t.Fatalf("invalid DER %x %v", der, e)
	}
	for _, bad := range [][]byte{{1, 2, 3}, {0, 0, 0, 0}, {1, 2}} {
		if _, e := rawECDSAToDER(bad, 2); e == nil {
			t.Fatal("accepted invalid signature")
		}
	}
	if bytes.Equal(raw, der) {
		t.Fatal("unconverted")
	}
}
func TestHashAlgorithm(t *testing.T) {
	for _, v := range []struct {
		h    crypto.Hash
		name string
		size int
	}{{crypto.SHA256, "SHA256", 32}, {crypto.SHA384, "SHA384", 48}, {crypto.SHA512, "SHA512", 64}} {
		n, e := hashAlgorithm(v.h, v.size)
		if e != nil || n != v.name {
			t.Fatalf("%v %q %v", v.h, n, e)
		}
	}
	if _, e := hashAlgorithm(crypto.SHA1, 20); e == nil {
		t.Fatal("SHA1 accepted")
	}
	if _, e := hashAlgorithm(crypto.SHA256, 31); e == nil {
		t.Fatal("short digest accepted")
	}
}
