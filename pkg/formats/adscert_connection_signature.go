package formats

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

const (
	attributeFrom             = "from"
	attributeFromKey          = "from_key"
	attributeInvoking         = "invoking"
	attributeTo               = "to"
	attributeToKey            = "to_key"
	attributeTimestamp        = "timestamp"
	attributeNonce            = "nonce"
	attributeStatus           = "status"
	attributeSignatureForBody = "sigb"
	attributeSignatureForURL  = "sigu"
	hmacLength                = 12
)

type AuthenticatedConnectionSignature struct {
	from             string
	fromKey          string
	invoking         string
	to               string
	toKey            string
	timestamp        string
	nonce            string
	status           string
	signatureForBody string
	signatureForURL  string
}

func (s *AuthenticatedConnectionSignature) GetAttributeInvoking() string {
	return s.invoking
}

func (s *AuthenticatedConnectionSignature) GetAttributeFrom() string {
	return s.from
}

func (s *AuthenticatedConnectionSignature) EncodeMessage() string {
	values := url.Values{}
	conditionallyAdd(&values, attributeFrom, s.from)
	conditionallyAdd(&values, attributeFromKey, s.fromKey)
	conditionallyAdd(&values, attributeInvoking, s.invoking)
	conditionallyAdd(&values, attributeTo, s.to)
	conditionallyAdd(&values, attributeToKey, s.toKey)
	conditionallyAdd(&values, attributeTimestamp, s.timestamp)
	conditionallyAdd(&values, attributeNonce, s.nonce)
	conditionallyAdd(&values, attributeStatus, s.status)
	return values.Encode()
}

func (s *AuthenticatedConnectionSignature) encodeSignatures() string {
	values := url.Values{}
	conditionallyAdd(&values, attributeSignatureForBody, s.signatureForBody)
	conditionallyAdd(&values, attributeSignatureForURL, s.signatureForURL)
	return values.Encode()
}

func (s *AuthenticatedConnectionSignature) appendSignatures(unsignedMessage string) string {
	return unsignedMessage + "; " + s.encodeSignatures()
}

func (s *AuthenticatedConnectionSignature) AddParametersForSignature(
	fromKey string, to string, toKey string, timestamp string, nonce string) {
	s.fromKey = fromKey
	s.to = to
	s.toKey = toKey
	s.timestamp = timestamp
	s.nonce = nonce
}

func (s *AuthenticatedConnectionSignature) CompareSignatures(signatureForBody []byte, signatureForURL []byte) (bool, bool) {
	bodyMatch := hmac.Equal([]byte(B64truncate(signatureForBody, hmacLength)), []byte(s.signatureForBody))
	urlMatch := hmac.Equal([]byte(B64truncate(signatureForURL, hmacLength)), []byte(s.signatureForURL))
	return bodyMatch, urlMatch
}

func EncodeSignatureSuffix(
	signatureForBody []byte, signatureForURL []byte) string {
	values := url.Values{}
	conditionallyAdd(&values, attributeSignatureForBody, B64truncate(signatureForBody, hmacLength))
	conditionallyAdd(&values, attributeSignatureForURL, B64truncate(signatureForURL, hmacLength))
	return "; " + values.Encode()
}

func NewAuthenticatedConnectionSignature(status string, from string, invoking string) (*AuthenticatedConnectionSignature, error) {
	s := &AuthenticatedConnectionSignature{}

	s.status = status
	s.from = from
	s.invoking = invoking

	return s, nil
}

func DecodeAuthenticatedConnectionSignature(encodedMessage string) (*AuthenticatedConnectionSignature, error) {
	splitSignature := strings.Split(encodedMessage, ";")
	if len(splitSignature) != 2 {
		return nil, fmt.Errorf("wrong number of signature message tokens")
	}

	message := strings.TrimSpace(splitSignature[0])
	sigs := strings.TrimSpace(splitSignature[1])

	values, err := url.ParseQuery(message)
	if err != nil {
		return nil, fmt.Errorf("query string parse failure: %v", err)
	}

	parsedSigs, err := url.ParseQuery(sigs)
	if err != nil {
		return nil, fmt.Errorf("signature string parse failure: %v", err)
	}

	s := &AuthenticatedConnectionSignature{}

	s.from = getFirstMapElement(values[attributeFrom])
	s.fromKey = getFirstMapElement(values[attributeFromKey])
	s.invoking = getFirstMapElement(values[attributeInvoking])
	s.to = getFirstMapElement(values[attributeTo])
	s.toKey = getFirstMapElement(values[attributeToKey])
	s.timestamp = getFirstMapElement(values[attributeTimestamp])
	s.nonce = getFirstMapElement(values[attributeNonce])
	s.status = getFirstMapElement(values[attributeStatus])

	s.signatureForBody = getFirstMapElement(parsedSigs[attributeSignatureForBody])
	s.signatureForURL = getFirstMapElement(parsedSigs[attributeSignatureForURL])
	return s, nil
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

func B64truncate(rawMAC []byte, length int) string {
	b64MAC := base64.RawURLEncoding.EncodeToString(rawMAC)
	return b64MAC[:length]
}
