package adscertcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/cmlight/go-adscert/pkg/adscertcounterparty"
	"github.com/golang/glog"
)

const hmacLength = 12

type AuthenticatedConnectionsSignatory interface {
	EmbossSigningPackage(request *AuthenticatedConnectionSigningPackage) (*AuthenticatedConnectionSignatureResponse, error)
	VerifySigningPackage(request *AuthenticatedConnectionVerificationPackage) (*AuthenticatedConnectionVerificationResponse, error)
}

func NewLocalAuthenticatedConnectionsSignatory(originCallsign string, originKeyID string) AuthenticatedConnectionsSignatory {
	_, privateKey := GenerateFakeKeyPairFromDomainNameForTesting(originCallsign)
	return &localAuthenticatedConnectionsSignatory{
		counterpartyManager: adscertcounterparty.NewCounterpartyManager(NewFakeKeyGeneratingDnsResolver(), privateKey),
		originCallsign:      originCallsign,
		originKeyID:         originKeyID,
	}
}

type localAuthenticatedConnectionsSignatory struct {
	originCallsign string
	originKeyID    string // TODO: clean this up

	counterpartyManager adscertcounterparty.CounterpartyAPI
}

func (s *localAuthenticatedConnectionsSignatory) EmbossSigningPackage(request *AuthenticatedConnectionSigningPackage) (*AuthenticatedConnectionSignatureResponse, error) {
	// Note: this is basically going to be the same process for signing and verifying except the lookup method.
	response := &AuthenticatedConnectionSignatureResponse{}

	// Look up my ads.cert info.

	// Look up invocation hostname's counterparties
	// TODO: psl cleanup
	invocationCounterparty, err := s.counterpartyManager.LookUpInvocationCounterpartyByHostname(request.RequestInfo.InvocationHostname)
	if err != nil {
		return nil, err
	}

	for _, counterparty := range invocationCounterparty.GetSignatureCounterparties() {
		response.SignatureMessages = append(response.SignatureMessages, s.embossSingleMessage(request, counterparty))
	}

	return response, nil
}

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *AuthenticatedConnectionSigningPackage, counterparty adscertcounterparty.SignatureCounterparty) string {

	// Assemble final unsigned message
	values := url.Values{}
	values.Add("status", string(counterparty.GetStatus()))
	values.Add("invoking", request.RequestInfo.InvocationHostname)
	values.Add("from", s.originCallsign)
	values.Add("from_key", s.originKeyID)

	var message string

	if counterparty.HasSharedSecret() {
		values.Add("to", counterparty.GetAdsCertIdentityDomain())
		values.Add("to_key", counterparty.KeyID())
		values.Add("timestamp", request.Timestamp)
		values.Add("nonce", request.Nonce)

		requestKey := append(counterparty.SharedSecret()[:])

		h := hmac.New(sha256.New, requestKey)

		message = values.Encode()

		// Generate final signature
		h.Write([]byte(message))
		h.Write(request.RequestInfo.BodyHash[:])
		bodyHMAC := h.Sum(nil)

		h.Write(request.RequestInfo.URLHash[:])
		urlHMAC := h.Sum(nil)

		message = message + "; sigb=" + B64truncate(bodyHMAC, hmacLength) + "&sigu=" + B64truncate(urlHMAC, hmacLength)
	} else {
		message = values.Encode()
	}

	return message
}

func (s *localAuthenticatedConnectionsSignatory) VerifySigningPackage(request *AuthenticatedConnectionVerificationPackage) (*AuthenticatedConnectionVerificationResponse, error) {
	// glog.Info("Trying verification")
	response := &AuthenticatedConnectionVerificationResponse{}

	splitSignature := strings.Split(request.SignatureMessage, ";")
	if len(splitSignature) != 2 {
		return response, fmt.Errorf("wrong number of signature message tokens")
	}

	message := strings.TrimSpace(splitSignature[0])
	sigs := strings.TrimSpace(splitSignature[1])

	// Parse the message to figure out counterparty details.
	values, err := url.ParseQuery(message)
	if err != nil {
		// TODO: Make this into a normal return code
		return response, fmt.Errorf("query string parse failure: %v", err)
	}

	parsedSigs, err := url.ParseQuery(sigs)
	if err != nil {
		// TODO: Make this into a normal return code
		return response, fmt.Errorf("signature string parse failure: %v", err)
	}

	// Validate invocation hostname matches request
	if getFirstMapElement(values["invoking"]) != request.RequestInfo.InvocationHostname {
		glog.Infof("Invocation hostname %s != %s", getFirstMapElement(values["invoking"]), request.RequestInfo.InvocationHostname)
		// Unrelated signature error
		return response, nil
	}

	from := getFirstMapElement(values["from"])
	if from == "" {
		glog.Info("missing origin")
		// missing origin domain
		return response, nil
	}

	// Look up originator by callsign
	signatureCounterparty, err := s.counterpartyManager.LookUpSignatureCounterpartyByCallsign(from)
	if err != nil {
		return response, err
	}

	if !signatureCounterparty.HasSharedSecret() {
		glog.Infof("No shared secret yet with %s", from)
		return response, nil
	}

	// Look up my key details (try to hide this behind the counterparty API), e.g. SharedSecretFor(myKeyId, theirKeyId)

	// Validate the overall signature
	//  remove signature suffix
	//  HMAC against shared secret
	requestKey := append(signatureCounterparty.SharedSecret()[:])

	h := hmac.New(sha256.New, requestKey)
	h.Write([]byte(message))
	h.Write(request.RequestInfo.BodyHash[:])
	bodyHMACPrefix := B64truncate(h.Sum(nil), hmacLength)

	h.Write(request.RequestInfo.URLHash[:])
	urlHMACPrefix := B64truncate(h.Sum(nil), hmacLength)

	sigb := parsedSigs["sigb"]
	if len(sigb) != 1 {
		glog.Warning("expected exactly one sigb")
		return response, nil
	}

	if hmac.Equal([]byte(bodyHMACPrefix), []byte(sigb[0])) {
		response.BodyValid = true
	}

	sigu := parsedSigs["sigu"]
	if len(sigb) != 1 {
		glog.Warning("expected exactly one sigu")
		return response, nil
	}

	if hmac.Equal([]byte(urlHMACPrefix), []byte(sigu[0])) {
		response.URLValid = true
	}

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
