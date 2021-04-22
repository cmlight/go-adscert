package adscertcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
)

const hmacLength = 12

type AuthenticatedConnectionsSignatory interface {
	EmbossSigningPackage(request *AuthenticatedConnectionSigningPackage) (*AuthenticatedConnectionSignatureResponse, error)
	VerifySigningPackage(request *AuthenticatedConnectionVerificationPackage) (*AuthenticatedConnectionVerificationResponse, error)
}

func NewLocalAuthenticatedConnectionsSignatory() AuthenticatedConnectionsSignatory {
	return &localAuthenticatedConnectionsSignatory{
		counterpartyManager: NewCounterpartyManager(),
	}
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
	counterparties, err := s.counterpartyManager.FindCounterpartiesByInvocationHostname(request.RequestInfo.InvocationHostname)
	if err != nil {
		return nil, err
	}

	for _, counterparty := range counterparties {
		response.SignatureMessages = append(response.SignatureMessages, s.embossSingleMessage(request, counterparty))
	}

	return response, nil
}

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *AuthenticatedConnectionSigningPackage, counterparty Counterparty) string {

	// Assemble final unsigned message
	values := url.Values{}
	values.Add("status", counterparty.Status())
	values.Add("invoking", request.RequestInfo.InvocationHostname)
	values.Add("from", s.originCallsign)
	values.Add("from_key", s.originKeyID)

	var message string

	if counterparty.HasSharedSecret() {
		values.Add("to", counterparty.GetAdsCertIdentityDomain())
		values.Add("to_key", counterparty.KeyID())
		values.Add("timestamp", request.Timestamp)
		values.Add("nonce", request.Nonce)

		h := hmac.New(sha256.New, counterparty.SharedSecret()[:])

		// HMAC URL hash
		urlHMAC := h.Sum(request.RequestInfo.URLHash[:])

		// HMAC Body hash
		bodyHMAC := h.Sum(request.RequestInfo.BodyHash[:])

		values.Add("url_mac", B64truncate(urlHMAC, hmacLength))
		values.Add("body_mac", B64truncate(bodyHMAC, hmacLength))

		message = values.Encode()

		// Generate final signature
		finalHMAC := h.Sum([]byte(message))
		message = message + "&sig=" + B64truncate(finalHMAC, hmacLength)
	} else {
		message = values.Encode()
	}

	return message
}

func (s *localAuthenticatedConnectionsSignatory) VerifySigningPackage(request *AuthenticatedConnectionVerificationPackage) (*AuthenticatedConnectionVerificationResponse, error) {
	response := &AuthenticatedConnectionVerificationResponse{}

	// Parse the message to figure out counterparty details.
	values, err := url.ParseQuery(request.SignatureMessage)
	if err != nil {
		// TODO: Make this into a normal return code
		return nil, fmt.Errorf("query string parse failure: %v", err)
	}

	// Validate invocation hostname matches request
	if getFirstMapElement(values["invoking"]) != request.RequestInfo.InvocationHostname {

	}

	// Look up my key details (try to hide this behind the counterparty API), e.g. SharedSecretFor(myKeyId, theirKeyId)

	// Look up originator by callsign

	// Validate the overall signature
	//  remove signature suffix
	//  HMAC against shared secret
	//  Check that HMACs match using hmac.Equal
	//  Record outcome

	// Validate the URL hash

	// Validate the body hash

	return response, nil
}

func B64truncate(rawMAC []byte, length int) string {
	b64MAC := base64.RawURLEncoding.EncodeToString(rawMAC)
	return b64MAC[:length]
}

func getFirstMapElement(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
