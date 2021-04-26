package adscertcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/cmlight/go-adscert/pkg/adscertcounterparty"
	"github.com/cmlight/go-adscert/pkg/formats"
	"github.com/golang/glog"
)

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

	// TODO: psl cleanup
	invocationCounterparty, err := s.counterpartyManager.LookUpInvocationCounterpartyByHostname(request.RequestInfo.InvocationHostname)
	if err != nil {
		return nil, err
	}

	for _, counterparty := range invocationCounterparty.GetSignatureCounterparties() {
		message, err := s.embossSingleMessage(request, counterparty)
		if err != nil {
			return nil, err
		}
		response.SignatureMessages = append(response.SignatureMessages, message)
	}

	return response, nil
}

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *AuthenticatedConnectionSigningPackage, counterparty adscertcounterparty.SignatureCounterparty) (string, error) {

	acs, err := formats.NewAuthenticatedConnectionSignature(counterparty.GetStatus().String(), s.originCallsign, request.RequestInfo.InvocationHostname)
	if err != nil {
		return "", fmt.Errorf("error constructing authenticated connection signature format: %v", err)
	}

	if !counterparty.HasSharedSecret() {
		return acs.EncodeMessage(), nil
	}

	if err = acs.AddParametersForSignature(s.originKeyID,
		counterparty.GetAdsCertIdentityDomain(),
		counterparty.KeyID(),
		request.Timestamp,
		request.Nonce); err != nil {
		return "", fmt.Errorf("error adding signature params: %v", err)
	}

	message := acs.EncodeMessage()
	bodyHMAC, urlHMAC := generateSignatures(counterparty, []byte(message), request.RequestInfo.BodyHash[:], request.RequestInfo.URLHash[:])
	return message + formats.EncodeSignatureSuffix(bodyHMAC, urlHMAC), nil
}

func (s *localAuthenticatedConnectionsSignatory) VerifySigningPackage(request *AuthenticatedConnectionVerificationPackage) (*AuthenticatedConnectionVerificationResponse, error) {
	response := &AuthenticatedConnectionVerificationResponse{}

	acs, err := formats.DecodeAuthenticatedConnectionSignature(request.SignatureMessage)
	if err != nil {
		return response, fmt.Errorf("signature decode failure: %v", err)
	}

	glog.Infof("parsed ACS: %+v", acs)

	// Validate invocation hostname matches request
	if acs.GetAttributeInvoking() != request.RequestInfo.InvocationHostname {
		// TODO: Unrelated signature error
		glog.Info("unrelated signature")
		return response, fmt.Errorf("Unrelated signature error")
	}

	// Look up originator by callsign
	signatureCounterparty, err := s.counterpartyManager.LookUpSignatureCounterpartyByCallsign(acs.GetAttributeFrom())
	if err != nil {
		glog.Info("counterparty lookup error")
		return response, err
	}

	if !signatureCounterparty.HasSharedSecret() {
		// TODO: shared secret missing error
		glog.Info("no shared secret")
		return response, nil
	}

	glog.Info("checking signatures")
	bodyHMAC, urlHMAC := generateSignatures(signatureCounterparty, []byte(acs.EncodeMessage()), request.RequestInfo.BodyHash[:], request.RequestInfo.URLHash[:])
	response.BodyValid, response.URLValid = acs.CompareSignatures(bodyHMAC, urlHMAC)
	return response, nil
}

func generateSignatures(counterparty adscertcounterparty.SignatureCounterparty, message []byte, bodyHash []byte, urlHash []byte) ([]byte, []byte) {
	h := hmac.New(sha256.New, counterparty.SharedSecret()[:])

	h.Write([]byte(message))
	h.Write(bodyHash)
	bodyHMAC := h.Sum(nil)

	h.Write(urlHash)
	urlHMAC := h.Sum(nil)

	return bodyHMAC, urlHMAC
}
