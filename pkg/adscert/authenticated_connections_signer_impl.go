package adscert

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"golang.org/x/net/publicsuffix"
)

type authenticatedConnectionsSigner struct {
	// adscertcrypto adscertcrypto.AdsCertCrypto

	signatory adscertcrypto.AuthenticatedConnectionsSignatory
}

func assembleRequestInfo(params *AuthenticatedConnectionSignatureParams, requestInfo *adscertcrypto.RequestInfo) error {
	parsedURL, tldPlusOne, err := parseURLComponents(params.DestinationURL)
	if err != nil {
		// TODO: generate a signature message indicating URL parse failure.
		return fmt.Errorf("unable to parse destination URL: %v", err)
	}

	requestInfo.InvocationHostname = tldPlusOne

	hashRequests := []hashRequest{{
		hashDestination: requestInfo.URLHash[:],
		messageToHash:   []byte(parsedURL.String()),
	}}

	if len(params.RequestBody) != 0 {
		hashRequests = append(hashRequests, hashRequest{
			hashDestination: requestInfo.BodyHash[:],
			messageToHash:   params.RequestBody,
		})
	}

	calculateScopedHashes([]string{}, hashRequests)
	return nil
}

func (c *authenticatedConnectionsSigner) SignAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionSignature, error) {
	response := AuthenticatedConnectionSignature{}
	signatureRequest := adscertcrypto.AuthenticatedConnectionSigningPackage{}

	// Optional HMAC instead of hash for delegated signing environments
	// or if this otherwise provides better security.  I think we will
	// probably want to do this for everything to avoid a preimage attack, but
	// not sure if it should happen in front of or behind the emboss service.

	assembleRequestInfo(&params, &signatureRequest.RequestInfo)

	// Invoke the embossing service
	embossReply, err := c.signatory.EmbossSigningPackage(&signatureRequest)
	if err != nil {
		return response, fmt.Errorf("error embossing signing package: %v", err)
	}

	response.SignatureMessage = embossReply.SignatureMessage

	return response, nil
}

func (c *authenticatedConnectionsSigner) VerifyAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionVerification, error) {
	response := AuthenticatedConnectionVerification{}
	verificationRequest := adscertcrypto.AuthenticatedConnectionVerificationPackage{}

	assembleRequestInfo(&params, &verificationRequest.RequestInfo)
	verificationRequest.SignatureMessage = params.SignatureMessageToVerify

	verifyReply, err := c.signatory.VerifySigningPackage(&verificationRequest)
	if err != nil {
		return response, fmt.Errorf("error verifying signing package: %v", err)
	}

	response.Valid = verifyReply.Valid

	return response, nil
}

func parseURLComponents(destinationURL string) (*url.URL, string, error) {
	parsedDestURL, err := url.Parse(destinationURL)
	if err != nil {
		return nil, "", err
	}
	tldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(parsedDestURL.Hostname())
	if err != nil {
		return nil, "", err
	}
	return parsedDestURL, tldPlusOne, nil
}

type hashRequest struct {
	hashDestination []byte
	messageToHash   []byte
}

func calculateScopedHashes(scopeKey []string, hashRequests []hashRequest) {
	joinedScopeKey := strings.Join(scopeKey, "/")

	// TODO: evaluate if this is really needed
	h := hmac.New(sha256.New, []byte(joinedScopeKey))
	for _, req := range hashRequests {
		copy(req.hashDestination, h.Sum(req.messageToHash))
	}
}
