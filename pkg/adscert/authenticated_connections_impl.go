package adscert

import (
	"crypto/sha256"
	"net/url"

	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"golang.org/x/net/publicsuffix"
)

type authenticatedConnectionsManager struct {
	authenticatedConnectionsSigner   *authenticatedConnectionsSigner
	authenticatedConnectionsVerifier *authenticatedConnectionsVerifier
	adscertcrypto                    adscertcrypto.AdsCertCrypto
}

func (c *authenticatedConnectionsManager) AuthenticatedConnectionsSigner() AuthenticatedConnectionsSigner {
	return c.authenticatedConnectionsSigner
}

func (c *authenticatedConnectionsManager) AuthenticatedConnectionsVerifier() AuthenticatedConnectionsVerifier {
	return c.authenticatedConnectionsVerifier
}

// NewAuthenticatedConnectionsManager constructs a new thread-safe, singleton
// AuthenticatedConnectionsManager.
func NewAuthenticatedConnectionsManager() AuthenticatedConnectionsManager {
	return &authenticatedConnectionsManager{
		authenticatedConnectionsSigner:   &authenticatedConnectionsSigner{},
		authenticatedConnectionsVerifier: &authenticatedConnectionsVerifier{},
	}
}

type authenticatedConnectionsSigner struct{}

func (c *authenticatedConnectionsSigner) SignAuthenticatedConnection(destinationURL string, body []byte) (AuthenticatedConnectionSignature, error) {
	signatureRequest := adscertcrypto.AuthenticatedConnectionSignatureRequest{}
	// baseParams := origin,origink,dest,destk,ts,nonce
	// urlMAC := baseParams[,urlHash]
	// bodyMAC := baseParams[,bodyHash]

	// Hash body
	signatureRequest.BodyHash = sha256.Sum256(body)

	// Parse out destination host registerable domain and hash URL
	c.parseURLIntoSignatureRequest(destinationURL, &signatureRequest)

	return &authenticatedConnectionSignature{signatureMessage: "foo"}, nil
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

type authenticatedConnectionsVerifier struct{}

func (c *authenticatedConnectionsVerifier) VerifyAuthenticatedConnection(
	destinationURL string,
	body []byte,
	signature AuthenticatedConnectionSignature) (AuthenticatedConnectionVerification, error) {
	// TODO: implement this.
	return nil, nil
}

type authenticatedConnectionSignature struct {
	signatureMessage string
}

func (s *authenticatedConnectionSignature) String() string {
	return s.signatureMessage
}
