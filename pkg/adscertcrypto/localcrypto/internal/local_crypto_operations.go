package internal

// import (
// 	"fmt"
// 	"io"

// 	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
// 	"golang.org/x/crypto/curve25519"
// )

// type generic32ByteKey struct {
// 	keyMaterial [32]byte
// }

// func (k *generic32ByteKey) InternalCopyInto(dest []byte) {
// 	n := copy(dest, k.keyMaterial[:])
// 	if n != 32 {
// 		panic(fmt.Sprintf("Expected 32 bytes of key material, but copied %d", n))
// 	}
// }

// type localAdsCertCrypto struct {
// 	secureRandom           io.Reader
// 	keyPairGenerator       *localKeyPairGenerator
// 	sharedSecretCalculator *localSharedSecretCalculator
// }

// // NewAdsCertCryptoInternal provides an AdsCertCrypto implementation that
// // performsall crypto operations and key management in process with the app
// // using this API.
// func NewAdsCertCryptoInternal(secureRandom io.Reader) adscertcrypto.AdsCertCrypto {
// 	result := &localAdsCertCrypto{secureRandom: secureRandom}
// 	result.keyPairGenerator = &localKeyPairGenerator{parent: result}
// 	result.sharedSecretCalculator = &localSharedSecretCalculator{}
// 	return result
// }

// func (c *localAdsCertCrypto) KeyPairGenerator() adscertcrypto.KeyPairGenerator {
// 	return c.keyPairGenerator
// }

// func (c *localAdsCertCrypto) SharedSecretCalculator() adscertcrypto.SharedSecretCalculator {
// 	return c.sharedSecretCalculator
// }

// type localKeyPairGenerator struct {
// 	parent *localAdsCertCrypto
// }

// // GenerateNewKeyPair safely creates a new key pair from the platform's
// // cryptographically secure random number generator.
// func (c *localKeyPairGenerator) GenerateNewKeyPair() (adscertcrypto.AdsCertPublicKey, adscertcrypto.AdsCertPrivateKey, error) {
// 	privateKey := &generic32ByteKey{}
// 	publicKey := &generic32ByteKey{}
// 	n, err := io.ReadFull(c.parent.secureRandom, privateKey.keyMaterial[:])
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	if n != 32 {
// 		return nil, nil, fmt.Errorf("expected to generate 32 random values for key, was %d", n)
// 	}
// 	curve25519.ScalarBaseMult(&publicKey.keyMaterial, &privateKey.keyMaterial)

// 	return publicKey, privateKey, nil
// }

// type localSharedSecretCalculator struct{}

// // CalculateSharedSecret determines the shared secret calculation between the
// // specified public and private key.
// func (c *localSharedSecretCalculator) CalculateSharedSecret(publicKey adscertcrypto.AdsCertPublicKey, privateKey adscertcrypto.AdsCertPrivateKey) (adscertcrypto.AdsCertSharedSecret, error) {
// 	var publicKeyBytes, privateKeyBytes [32]byte
// 	publicKey.InternalCopyInto(publicKeyBytes[:])
// 	privateKey.InternalCopyInto(privateKeyBytes[:])
// 	sharedValue, err := curve25519.X25519(privateKeyBytes[:], publicKeyBytes[:])
// 	if err != nil {
// 		return nil, fmt.Errorf("error calculating shared secret: %v", err)
// 	}
// 	result := &generic32ByteKey{}
// 	copy(result.keyMaterial[:], sharedValue)
// 	return result, nil
// }
