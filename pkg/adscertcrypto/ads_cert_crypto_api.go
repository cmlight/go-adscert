package adscertcrypto

// AdsCertCrypto provides a fluent API for ads.cert cryptographic operations.
// This main interface composes the underlying ads.cert APIs into a convenient
// handle to be passed throughout integrating applications. These interfaces
// allow for different implementations of the underlying infrastructure. For
// instance, some environments may require cryptographic operations to be
// performed within a separate key escrow service, while other environments
// may be OK with allowing those operations in the same application process.
// These interfaces provide flexibility to create multiple implementation
// options to meet those requirements.
//
// All operations using these APIs can be assumed to be thread-safe.
type AdsCertCrypto interface {
	KeyPairGenerator() KeyPairGenerator
	SharedSecretCalculator() SharedSecretCalculator
}

// KeyPairGenerator generates new key pairs in a format that's conformant with
// the ads.cert specification.
type KeyPairGenerator interface {
	GenerateNewKeyPair() (AdsCertPublicKey, AdsCertPrivateKey, error)
}

// PublicKeyParser parses public keys conforming to the ads.cert specification
// as found within DNS records or other distribution channels.
type PublicKeyParser interface {
	ParseAdsCertPublicKey(keyMessage string) (AdsCertPublicKey, error)
}

// SharedSecretCalculator generates a shared secret between the system's own
// private key and a counterparty's public key.
type SharedSecretCalculator interface {
	CalculateSharedSecret(publicKey AdsCertPublicKey, privateKey AdsCertPrivateKey) (AdsCertSharedSecret, error)
}

// Counterparty represents a peer organization within the programmatic
// advertising ecosystem who may or may not participate within the ads.cert
// standard. A Counterparty safely encapsulates the public key material used for
// authenticating with the entity.
type Counterparty interface {
	GetAdsCertIdentityDomain() string
	// TODO: enumeration of counterparty capabilities
}

// AdsCertPublicKey provides an opaque, fluent interface around a public key
// used by ads.cert signature operations.
type AdsCertPublicKey interface {
	InternalBaseKey
}

// AdsCertPrivateKey provides an opaque, fluent interface around a private key
// used by ads.cert signature operations.
type AdsCertPrivateKey interface {
	InternalBaseKey
}

// AdsCertSharedSecret provides an opaque, fluent interface around a shared
// secret value used within ads.cert signature operations.
type AdsCertSharedSecret interface {
	InternalBaseKey
}
