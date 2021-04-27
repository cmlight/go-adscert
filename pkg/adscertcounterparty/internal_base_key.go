package adscertcounterparty

import (
	"crypto/rand"
	"fmt"

	"github.com/cmlight/go-adscert/pkg/formats"
	"github.com/golang/glog"
	"golang.org/x/crypto/curve25519"
)

// // x25519PublicKey provides a lightweight, typed wrapper around key material to
// // permit pass-by-value.
// type x25519PublicKey struct {
// 	publicKey     [32]byte
// 	keyIdentifier string
// }

// // x25519PrivateKey provides a lightweight, typed wrapper around key material to
// // permit pass-by-value.
// type x25519PrivateKey struct {
// 	privateKey [32]byte
// 	keyIdentifier string
// }

// x25519SharedSecret provides a lightweight, typed wrapper around computed
// shared secret material to permit pass-by-value.
type x25519Key struct {
	keyBytes   [32]byte
	alias      keyAlias
	tupleAlias keyTupleAlias
}

func (x *x25519Key) Secret() *[32]byte {
	return &x.keyBytes
}

func (x *x25519Key) LocalKeyID() string {
	return string(x.tupleAlias.myKeyAlias)
}

func (x *x25519Key) RemoteKeyID() string {
	return string(x.tupleAlias.theirKeyAlias)
}

type keyAlias string

type keyTupleAlias struct {
	myKeyAlias    keyAlias
	theirKeyAlias keyAlias
}

func newKeyTupleAlias(myKeyId keyAlias, theirKeyId keyAlias) keyTupleAlias {
	return keyTupleAlias{myKeyAlias: myKeyId, theirKeyAlias: theirKeyId}
}

type keyMap map[keyAlias]*x25519Key

type keyTupleMap map[keyTupleAlias]*x25519Key

func asKeyMap(adsCertKeys formats.AdsCertKeys) keyMap {
	result := keyMap{}

	for _, k := range adsCertKeys.PublicKeys {
		x25519Key := &x25519Key{
			alias: keyAlias(k.KeyAlias),
		}
		if n := copy(x25519Key.keyBytes[:], k.PublicKeyBytes); n != 32 {
			glog.Warningf("wrong number of bytes copied for key alias %s: %d != 32", k.KeyAlias, n)
			continue
		}
		result[x25519Key.alias] = x25519Key
	}

	return result
}

func calculateSharedSecret(myPrivate *x25519Key, theirPublic *x25519Key) (*x25519Key, error) {
	secret, err := curve25519.X25519(myPrivate.keyBytes[:], theirPublic.keyBytes[:])
	if err != nil {
		return nil, err
	}

	result := &x25519Key{
		tupleAlias: newKeyTupleAlias(myPrivate.alias, theirPublic.alias),
	}
	copy(result.keyBytes[:], secret)

	return result, err
}

func generateKeyPair() (string, string, error) {
	privateBytes := &[32]byte{}
	if n, err := rand.Read(privateBytes[:]); err != nil {
		return "", "", err
	} else if n != 32 {
		return "", "", fmt.Errorf("wrong key size generated: %d != 32", n)
	}

	publicBytes := &[32]byte{}
	curve25519.ScalarBaseMult(publicBytes, privateBytes)

	return formats.EncodeKeyBase64(privateBytes[:]), formats.EncodeKeyBase64(publicBytes[:]), nil
}

type keyReceiver interface {
	receivingSlice() []byte
	setKeyAlias(alias string)
	getKeyAlias() string
}

func privateKeysToKeyMap(privateKeys []string) (keyMap, error) {
	result := keyMap{}

	for _, privateKeyBase64 := range privateKeys {
		privateKey, err := parseKeyFromString(privateKeyBase64)
		if err != nil {
			return nil, err
		}

		publicBytes := &[32]byte{}
		curve25519.ScalarBaseMult(publicBytes, &privateKey.keyBytes)

		keyAlias := keyAlias(formats.ExtractKeyAliasFromPublicKeyBase64(formats.EncodeKeyBase64(publicBytes[:])))
		privateKey.alias = keyAlias
		result[keyAlias] = privateKey
	}

	return result, nil
}

func parseKeyFromString(base64EncodedKey string) (*x25519Key, error) {
	var key x25519Key
	rawKeyBytes, err := formats.ParseBase64EncodedKey(base64EncodedKey, 32)
	if err != nil {
		return nil, err
	}
	if n := copy(key.keyBytes[:], rawKeyBytes); n != 32 {
		return nil, fmt.Errorf("wrong number of bytes copied: %d != 32", n)
	}
	return &key, nil
}
