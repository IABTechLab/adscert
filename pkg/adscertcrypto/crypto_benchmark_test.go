package adscertcrypto_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func BenchmarkCurve25519ScalarBaseMult(b *testing.B) {
	var dest, src [32]byte
	for i := 0; i < b.N; i++ {
		curve25519.ScalarBaseMult(&dest, &src)
	}
}

func BenchmarkSHA256_32byte(b *testing.B) {
	var data [32]byte
	for i := 0; i < b.N; i++ {
		sha256.Sum256(data[:])
	}
}

func BenchmarkHMAC_SHA256_32byte(b *testing.B) {
	var key, data [32]byte
	for i := 0; i < b.N; i++ {
		h := hmac.New(sha256.New, key[:])
		h.Write(data[:])
		h.Sum(nil)
		h.Reset()
	}
}

func BenchmarkHMAC_ReuseSHA256_32byte(b *testing.B) {
	var key, data [32]byte
	h := hmac.New(sha256.New, key[:])
	for i := 0; i < b.N; i++ {
		h.Write(data[:])
		h.Sum(nil)
		h.Reset()
	}
}
