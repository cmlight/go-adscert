package adscert

import (
	"crypto/sha256"
	"net/url"

	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"golang.org/x/net/publicsuffix"
)

func NewAuthenticatedConnectionsSigner(adscertcrypto adscertcrypto.AdsCertCrypto) AuthenticatedConnectionsSigner {
	return &authenticatedConnectionsSigner{}
}

type authenticatedConnectionsSigner struct {
	adscertcrypto adscertcrypto.AdsCertCrypto
}

func (c *authenticatedConnectionsSigner) SignAuthenticatedConnection(params SignAuthenticatedConnectionParams) (AuthenticatedConnectionSignature, error) {
	signatureRequest := adscertcrypto.AuthenticatedConnectionSignatureRequest{}
	// baseParams := origin,origink,dest,destk,ts,nonce
	// urlMAC := baseParams[,urlHash]
	// bodyMAC := baseParams[,bodyHash]

	// Hash body
	signatureRequest.BodyHash = sha256.Sum256(params.RequestBody)

	// Parse out destination host registerable domain and hash URL
	c.parseURLIntoSignatureRequest(params.DestinationURL, &signatureRequest)

	return AuthenticatedConnectionSignature{SignatureMessage: "foo"}, nil
}

func (c *authenticatedConnectionsSigner) parseURLIntoSignatureRequest(destinationURL string, signatureRequest *adscertcrypto.AuthenticatedConnectionSignatureRequest) {
	parsedDestURL, err := url.Parse(destinationURL)
	if err != nil {
		// Counter for URL parse failures
		// use error code for URL MAC
	} else {
		signatureRequest.InvocationHostname = parsedDestURL.Hostname()
		publicsuffix.EffectiveTLDPlusOne(parsedDestURL.Hostname())
		signatureRequest.URLHash = sha256.Sum256([]byte(parsedDestURL.String()))
	}

}
