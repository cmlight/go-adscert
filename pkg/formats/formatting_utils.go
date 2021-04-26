package formats

import (
	"encoding/base64"
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
