package adscertcrypto

import "golang.org/x/crypto/curve25519"

// x25519PublicKey provides a lightweight, typed wrapper around key material to
// permit pass-by-value.
type x25519PublicKey struct {
	publicKey   [32]byte
	initialized bool
}

// x25519PrivateKey provides a lightweight, typed wrapper around key material to
// permit pass-by-value.
type x25519PrivateKey struct {
	privateKey  [32]byte
	initialized bool
}

// x25519SharedSecret provides a lightweight, typed wrapper around computed
// shared secret material to permit pass-by-value.
type x25519SharedSecret struct {
	sharedSecret [32]byte
	initialized  bool
}

func calculateSharedSecret(myPrivate x25519PrivateKey, theirPublic x25519PublicKey) (x25519SharedSecret, error) {
	secret, err := curve25519.X25519(myPrivate.privateKey[:], theirPublic.publicKey[:])

	result := x25519SharedSecret{}
	if err == nil {
		copy(result.sharedSecret[:], secret)
		result.initialized = true
	}

	return result, err
}
