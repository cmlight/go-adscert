package internal_test

// import (
// 	"testing"

// 	"github.com/cmlight/go-adscert/pkg/adscertcrypto/localcrypto/internal"
// 	"github.com/google/go-cmp/cmp"
// )

// // fakeRandom generates a stream of incrementing byte values and can be
// // initialized with a custom starting value.
// type fakeRandom struct{ value byte }

// func (f *fakeRandom) Read(p []byte) (n int, err error) {
// 	for i := range p {
// 		p[i] = f.value
// 		f.value++
// 	}
// 	return len(p), nil
// }

// func TestGenerateNewKeyPair(t *testing.T) {
// 	acc := internal.NewAdsCertCryptoInternal(&fakeRandom{value: 0x10})
// 	publicKey, privateKey, err := acc.KeyPairGenerator().GenerateNewKeyPair()
// 	if err != nil {
// 		t.Fatalf("GenerateNewKeyPair(): unexpected error: %v", err)
// 	}
// 	var gotPubBytes, gotPrivBytes [32]byte
// 	publicKey.InternalCopyInto(gotPubBytes[:])
// 	privateKey.InternalCopyInto(gotPrivBytes[:])

// 	wantPubBytes := [32]byte{
// 		0xd8, 0x9e, 0x3b, 0xad, 0x79, 0x43, 0x7d, 0xbe, 0xd9, 0xf8, 0x43, 0x41, 0x83, 0x04, 0xf4, 0x60,
// 		0xff, 0x05, 0xc7, 0xfe, 0x81, 0xfe, 0x4a, 0x95, 0x77, 0xa8, 0x04, 0xcb, 0x93, 0x67, 0xff, 0x66,
// 	}

// 	wantPrivBytes := [32]byte{
// 		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
// 		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
// 	}

// 	if diff := cmp.Diff(wantPrivBytes, gotPrivBytes); diff != "" {
// 		t.Errorf("GenerateNewKeyPair() returned unexpected private key diff (-want +got):\n%s", diff)
// 	}
// 	if diff := cmp.Diff(wantPubBytes, gotPubBytes); diff != "" {
// 		t.Errorf("GenerateNewKeyPair() returned unexpected public key diff (-want +got):\n%s", diff)
// 	}

// 	sharedSecret, err := acc.SharedSecretCalculator().CalculateSharedSecret(publicKey, privateKey)
// 	if err != nil {
// 		t.Fatalf("CalculateSharedSecret(): unexpected error: %v", err)
// 	}
// 	var gotShareBytes [32]byte
// 	sharedSecret.InternalCopyInto(gotShareBytes[:])

// 	wantShareBytes := [32]byte{
// 		0x08, 0x76, 0x28, 0xd3, 0xe3, 0x1e, 0x26, 0x97, 0x80, 0xc4, 0x30, 0x49, 0x3a, 0x27, 0x01, 0x03,
// 		0xa8, 0x70, 0xe6, 0x85, 0x59, 0x5d, 0x8a, 0xb4, 0x70, 0x1f, 0x4b, 0xe2, 0x6c, 0x08, 0x45, 0x53,
// 	}
// 	if diff := cmp.Diff(wantShareBytes, gotShareBytes); diff != "" {
// 		t.Errorf("CalculateSharedSecret() returned unexpected shared key diff (-want +got):\n%s", diff)
// 	}
// }
