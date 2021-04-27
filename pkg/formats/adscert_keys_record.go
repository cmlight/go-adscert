package formats

import (
	"errors"
	"strings"
)

var (
	ErrVersionPrefixOutOfOrder = errors.New("version prefix out of order")
	ErrVersionUnknown          = errors.New("unknown version string")
	ErrVersionMissing          = errors.New("missing version string")
	ErrKeyAlgorithmMissing     = errors.New("key algorithm missing")
	ErrHashAlgorithmMissing    = errors.New("hash algorithm missing")
	ErrPublicKeysMissing       = errors.New("public keys missing")
	ErrWrongKeySize            = errors.New("wrong key size")

	ErrASN1TrailingData      = errors.New("trailing data after ASN.1 of public key")
	ErrUnsupportedAlgorithm  = errors.New("unsupported key algorithm")
	ErrUnsupportedParameters = errors.New("unsupported key parameters")
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
	var versionOK, keyAlgoOK, hashAlgoOK bool
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
			versionOK = true
		case "k":
			if value != "x25519" {
				return nil, ErrUnsupportedAlgorithm
			}
			keyAlgoOK = true
		case "h":
			for _, algo := range strings.Split(value, ":") {
				if algo == "sha256" {
					hashAlgoOK = true
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
	if !versionOK {
		return nil, ErrVersionMissing
	}
	if !keyAlgoOK {
		return nil, ErrKeyAlgorithmMissing
	}
	if !hashAlgoOK {
		return nil, ErrHashAlgorithmMissing
	}
	if len(parsedKeys.PublicKeys) == 0 {
		return nil, ErrPublicKeysMissing
	}
	return parsedKeys, nil
}

func ExtractKeyAliasFromPublicKeyBase64(publicKeyBase64 string) string {
	return publicKeyBase64[:6]
}

// type publicKeyInfo struct {
// 	Raw       asn1.RawContent
// 	Algorithm pkix.AlgorithmIdentifier
// 	PublicKey asn1.BitString
// }

// var (
// 	// OID specified in RFC 8410.
// 	// See also http://oid-info.com/get/1.3.101.110
// 	oidPublicKeyX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
// )

// func parseEncodedKey(encodedKey string) (*publicKeyInfo, error) {
// 	derBytes, err := base64.RawStdEncoding.DecodeString(encodedKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("base64 public key decode failure: %v", err)
// 	}

// 	publicKeyInfo := &publicKeyInfo{}
// 	if rest, err := asn1.Unmarshal(derBytes, publicKeyInfo); err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal ASN.1 public key: %v", err)
// 	} else if len(rest) != 0 {
// 		return nil, ErrASN1TrailingData
// 	}

// 	if !oidPublicKeyX25519.Equal(publicKeyInfo.Algorithm.Algorithm) {
// 		return nil, ErrUnsupportedAlgorithm
// 	}

// 	if len(publicKeyInfo.Algorithm.Parameters.FullBytes) != 0 {
// 		return nil, ErrUnsupportedParameters
// 	}

// 	return publicKeyInfo, nil
// }
