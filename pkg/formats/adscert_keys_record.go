package formats

import (
	"errors"
	"strings"
)

var (
	ErrEmptyInput               = errors.New("empty input")
	ErrVersionPrefixOutOfOrder  = errors.New("version prefix out of order")
	ErrVersionUnknown           = errors.New("unknown version string")
	ErrVersionMissing           = errors.New("missing version string or too many")
	ErrKeyAlgorithmWrongNumber  = errors.New("key algorithm missing or too many")
	ErrHashAlgorithmWrongNumber = errors.New("hash algorithm missing or too many")
	ErrPublicKeysMissing        = errors.New("public keys missing")
	ErrWrongKeySize             = errors.New("wrong key size")
	ErrZeroValueKey             = errors.New("zero-value key")
	ErrEmptyKey                 = errors.New("empty value for key")
	ErrUnsupportedAlgorithm     = errors.New("unsupported key algorithm")
	ErrBase64DecodeFailure      = errors.New("(base64 decode failure)")
)

type ParsedPublicKey struct {
	PublicKeyBytes []byte
	KeyAlias       string
}

type AdsCertKeys struct {
	PublicKeys []ParsedPublicKey
}

func DecodeAdsCertKeysRecord(keysRecord string) (*AdsCertKeys, error) {
	parsedKeys := &AdsCertKeys{}
	var versionOK, keyAlgoOK, hashAlgoOK int
	keysRecord = strings.TrimSpace(keysRecord)

	if keysRecord == "" {
		return nil, ErrEmptyInput
	}

	tokens := strings.Split(keysRecord, " ")
	for i, token := range tokens {
		pair := strings.SplitN(token, "=", 2)
		if len(pair) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(pair[0]))
		value := strings.TrimSpace(pair[1])

		switch key {
		case "v":
			if i != 0 {
				// Per ads.cert specification, version must be specified first.
				return nil, ErrVersionPrefixOutOfOrder
			}
			if value != "adcrtd" {
				return nil, ErrVersionUnknown
			}
			versionOK++
		case "k":
			if value != "x25519" {
				return nil, ErrUnsupportedAlgorithm
			}
			keyAlgoOK++
		case "h":
			for _, algo := range strings.Split(value, ":") {
				if algo == "sha256" {
					hashAlgoOK++
				}
				break
			}
		case "p":
			publicKeyBytes, err := ParseBase64EncodedKey(value, 32)
			if err != nil {
				return nil, err
			}
			parsedKeys.PublicKeys = append(parsedKeys.PublicKeys,
				ParsedPublicKey{
					PublicKeyBytes: publicKeyBytes,
					KeyAlias:       ExtractKeyAliasFromPublicKeyBase64(value),
				})
		}
	}
	if versionOK != 1 {
		return nil, ErrVersionMissing
	}
	if keyAlgoOK != 1 {
		return nil, ErrKeyAlgorithmWrongNumber
	}
	if hashAlgoOK != 1 {
		return nil, ErrHashAlgorithmWrongNumber
	}
	if len(parsedKeys.PublicKeys) == 0 {
		return nil, ErrPublicKeysMissing
	}
	return parsedKeys, nil
}

func ExtractKeyAliasFromPublicKeyBase64(publicKeyBase64 string) string {
	return publicKeyBase64[:6]
}
