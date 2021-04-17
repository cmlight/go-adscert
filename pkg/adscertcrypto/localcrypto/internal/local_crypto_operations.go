package internal

import (
	"fmt"
	"io"

	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type generic32ByteKey struct {
	keyMaterial [32]byte
}

func (k *generic32ByteKey) InternalCopyInto(dest []byte) {
	n := copy(dest, k.keyMaterial[:])
	if n != 32 {
		panic(fmt.Sprintf("Expected 32 bytes of key material, but copied %d", n))
	}
}

type localAdsCertCrypto struct {
	secureRandom                            io.Reader
	keyPairGenerator                        *localKeyPairGenerator
	sharedSecretCalculator                  *localSharedSecretCalculator
	authenticatedConnectionsSigner          *localAuthenticatedConnectionsSigner
	authenticatedConnectionsSignatureParser *localAuthenticatedConnectionsSignatureParser
	authenticatedConnectionsVerifier        *localAuthenticatedConnectionsVerifier
}

// NewAdsCertCryptoInternal provides an AdsCertCrypto implementation that
// performsall crypto operations and key management in process with the app
// using this API.
func NewAdsCertCryptoInternal(secureRandom io.Reader) adscertcrypto.AdsCertCrypto {
	result := &localAdsCertCrypto{secureRandom: secureRandom}
	result.keyPairGenerator = &localKeyPairGenerator{parent: result}
	result.sharedSecretCalculator = &localSharedSecretCalculator{}
	result.authenticatedConnectionsSigner = &localAuthenticatedConnectionsSigner{}
	result.authenticatedConnectionsSignatureParser = &localAuthenticatedConnectionsSignatureParser{}
	result.authenticatedConnectionsVerifier = &localAuthenticatedConnectionsVerifier{}
	return result
}

func (c *localAdsCertCrypto) KeyPairGenerator() adscertcrypto.KeyPairGenerator {
	return c.keyPairGenerator
}

func (c *localAdsCertCrypto) SharedSecretCalculator() adscertcrypto.SharedSecretCalculator {
	return c.sharedSecretCalculator
}

func (c *localAdsCertCrypto) AuthenticatedConnectionsSigner() adscertcrypto.AuthenticatedConnectionsSigner {
	return c.authenticatedConnectionsSigner
}

func (c *localAdsCertCrypto) AuthenticatedConnectionsSignatureParser() adscertcrypto.AuthenticatedConnectionsSignatureParser {
	return c.authenticatedConnectionsSignatureParser
}

func (c *localAdsCertCrypto) AuthenticatedConnectionsVerifier() adscertcrypto.AuthenticatedConnectionsVerifier {
	return c.authenticatedConnectionsVerifier
}

type localKeyPairGenerator struct {
	parent *localAdsCertCrypto
}

// GenerateNewKeyPair safely creates a new key pair from the platform's
// cryptographically secure random number generator.
func (c *localKeyPairGenerator) GenerateNewKeyPair() (adscertcrypto.AdsCertPublicKey, adscertcrypto.AdsCertPrivateKey, error) {
	pub, prv, err := box.GenerateKey(c.parent.secureRandom)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key pair: %v", err)
	}

	if len(pub) != 32 || len(prv) != 32 {
		return nil, nil, fmt.Errorf("expected to receive 32 byte keys, but sizes were %d and %d bytes", len(pub), len(prv))
	}

	publicKey := &generic32ByteKey{}
	if n := copy(publicKey.keyMaterial[:], pub[:]); n != 32 {
		return nil, nil, fmt.Errorf("expected to copy 32 byte public key, but copied %d bytes", n)
	}

	privateKey := &generic32ByteKey{}
	if n := copy(privateKey.keyMaterial[:], prv[:]); n != 32 {
		return nil, nil, fmt.Errorf("expected to copy 32 byte private key, but copied %d bytes", n)
	}

	return publicKey, privateKey, nil
}

type localSharedSecretCalculator struct{}

// CalculateSharedSecret determines the shared secret calculation between the
// specified public and private key.
func (c *localSharedSecretCalculator) CalculateSharedSecret(publicKey adscertcrypto.AdsCertPublicKey, privateKey adscertcrypto.AdsCertPrivateKey) (adscertcrypto.AdsCertSharedSecret, error) {
	var publicKeyBytes, privateKeyBytes [32]byte
	publicKey.InternalCopyInto(publicKeyBytes[:])
	privateKey.InternalCopyInto(privateKeyBytes[:])
	sharedValue, err := curve25519.X25519(privateKeyBytes[:], publicKeyBytes[:])
	if err != nil {
		return nil, fmt.Errorf("error calculating shared secret: %v", err)
	}
	result := &generic32ByteKey{}
	copy(result.keyMaterial[:], sharedValue)
	return result, nil
}

type localAuthenticatedConnectionsSigner struct{}

func (c *localAuthenticatedConnectionsSigner) SignAuthenticatedConnection(counterparty adscertcrypto.Counterparty, destinationURL string, body []byte) (adscertcrypto.AuthenticatedConnectionSignature, error) {
	// TODO: implement this.
	return nil, nil
}

type localAuthenticatedConnectionsSignatureParser struct{}

func (c *localAuthenticatedConnectionsSignatureParser) ParseAuthenticatedConnectionSignature(urlEncodedSignatureText string) adscertcrypto.AuthenticatedConnectionSignature {
	// TODO: implement this.
	return nil
}

type localAuthenticatedConnectionsVerifier struct{}

func (c *localAuthenticatedConnectionsVerifier) VerifyAuthenticatedConnection(
	counterparty adscertcrypto.Counterparty,
	destinationURL string,
	body []byte,
	signature adscertcrypto.AuthenticatedConnectionSignature) (adscertcrypto.AuthenticatedConnectionVerification, error) {
	// TODO: implement this.
	return nil, nil
}
