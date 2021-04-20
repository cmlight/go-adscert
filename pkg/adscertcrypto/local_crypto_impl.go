package adscertcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

type AuthenticatedConnectionsSignatory interface {
	EmbossSigningPackage(request *AuthenticatedConnectionSigningPackage) (*AuthenticatedConnectionSignatureResponse, error)
}

type localAuthenticatedConnectionsSignatory struct {
	originCallsign string
	originKeyID    string // TODO: clean this up

	counterpartyManager CounterpartyManager
}

func (s *localAuthenticatedConnectionsSignatory) EmbossSigningPackage(request *AuthenticatedConnectionSigningPackage) (*AuthenticatedConnectionSignatureResponse, error) {
	// Note: this is basically going to be the same process for signing and verifying except the lookup method.
	response := &AuthenticatedConnectionSignatureResponse{}
	
	// Look up my ads.cert info.

	// Look up invocation hostname's counterparties
	// TODO: psl cleanup
	counterparties, err := s.counterpartyManager.FindCounterpartiesByInvocationHostname(request.InvocationHostname)
	if err != nil {
		return nil, err
	}

	// For each counterparty
	for _, counterparty := range counterparties {
		response.SignatureMessage = append(response.SignatureMessage, s.embossSingleMessage(request, counterparty))
	}

	// Emboss single message

	return response, nil
}

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *AuthenticatedConnectionSigningPackage, counterparty Counterparty) string {

	h := hmac.New(sha256.New, counterparty.SharedSecret()[:])
	// create the stub HMAC

	// HMAC URL hash
	urlHMAC := h.Sum(request.URLHash[:])

	// HMAC Body hash
	bodyHMAC := h.Sum(request.BodyHash[:])

	// Assemble final unsigned message
	values := url.Values{}
	values.Add("invoking", request.InvocationHostname)
	values.Add("from", s.originCallsign)
	values.Add("from_key", s.originKeyID)
	values.Add("to", counterparty.GetAdsCertIdentityDomain())
	values.Add("to_key", counterparty.KeyID())
	values.Add("url_mac", b64truncate(urlHMAC))
	values.Add("body_mac", b64truncate(bodyHMAC))
	unsignedMessage := values.Encode()

	finalHMAC := h.Sum([]byte(unsignedMessage))

	// Generate final signature
	return unsignedMessage + "&sig=" + b64truncate(finalHMAC)
}

func b64truncate(rawMAC []byte) string {
	b64MAC := base64.RawURLEncoding.EncodeToString(rawMAC)
	return b64MAC[:6]
}
