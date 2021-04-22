package adscert

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"golang.org/x/net/publicsuffix"
)

type authenticatedConnectionsSigner struct {
	// adscertcrypto adscertcrypto.AdsCertCrypto
	secureRandom io.Reader

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
	if err := assembleRequestInfo(&params, &signatureRequest.RequestInfo); err != nil {
		return response, fmt.Errorf("error parsing request URL: %v", err)
	}

	signatureRequest.Timestamp = time.Now().Format("060102T150405")

	var nonce [32]byte
	n, err := io.ReadFull(c.secureRandom, nonce[:])
	if err != nil {
		return response, fmt.Errorf("error generating random: %v", err)
	}
	if n != 32 {
		return response, fmt.Errorf("unexpected number of random values: %d", n)
	}

	signatureRequest.Nonce = adscertcrypto.B64truncate(nonce[:], 12)

	// Invoke the embossing service
	embossReply, err := c.signatory.EmbossSigningPackage(&signatureRequest)
	if err != nil {
		return response, fmt.Errorf("error embossing signing package: %v", err)
	}

	response.SignatureMessages = embossReply.SignatureMessages

	return response, nil
}

func (c *authenticatedConnectionsSigner) VerifyAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionVerification, error) {
	response := AuthenticatedConnectionVerification{}
	verificationRequest := adscertcrypto.AuthenticatedConnectionVerificationPackage{}

	if err := assembleRequestInfo(&params, &verificationRequest.RequestInfo); err != nil {
		return response, fmt.Errorf("error parsing request URL: %v", err)
	}
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
