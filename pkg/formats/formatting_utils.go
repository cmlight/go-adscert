package formats

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

func B64truncate(rawMAC []byte, length int) string {
	b64MAC := base64.RawURLEncoding.EncodeToString(rawMAC)
	return b64MAC[:length]
}

func conditionallyAdd(values *url.Values, key string, value string) {
	if value != "" {
		values.Add(key, value)
	}
}

func getFirstMapElement(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func ParseBase64EncodedKey(encodedKey string, length int) ([]byte, error) {
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("public key base64 decode failed: %v", err)
	}

	if len(publicKeyBytes) != length {
		return nil, ErrWrongKeySize
	}

	return publicKeyBytes, nil
}

func EncodeKeyBase64(keyBytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(keyBytes)
}
