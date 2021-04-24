package formats

import "net/url"

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

func (s *AuthenticatedConnectionSignature) EncodeSignatures() string {
	values := url.Values{}
	conditionallyAdd(&values, attributeSignatureForBody, s.signatureForBody)
	conditionallyAdd(&values, attributeSignatureForURL, s.signatureForURL)
	return values.Encode()
}

func (s *AuthenticatedConnectionSignature) EncodeMessageAndSignatures() string {
	return s.EncodeMessage() + "; " + s.EncodeSignatures()
}

func conditionallyAdd(values *url.Values, key string, value string) {
	if value != "" {
		values.Add(key, value)
	}
}
