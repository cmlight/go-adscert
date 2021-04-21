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
		hmac.New(sha256.New, key[:]).Sum(data[:])
	}
}

func BenchmarkHMAC_ReuseSHA256_32byte(b *testing.B) {
	var key, data [32]byte
	h := hmac.New(sha256.New, key[:])
	for i := 0; i < b.N; i++ {
		h.Sum(data[:])
	}
}
