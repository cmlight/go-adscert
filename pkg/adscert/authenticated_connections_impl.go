package adscert

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"

	"github.com/golang/glog"
)

type authenticatedConnectionsManager struct {
	authenticatedConnectionsSigner   *authenticatedConnectionsSigner
	authenticatedConnectionsVerifier *authenticatedConnectionsVerifier
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
	// TODO: implement this.

	// baseParams := origin,origink,dest,destk,ts,nonce
	// bodyMAC := baseParams[,bodyHash]
	// urlMAC := baseParams[,urlHash]

	// hash body
	bodyHash := sha256.Sum256(body)
	glog.Infof("body hash is %s", base64.RawURLEncoding.EncodeToString(bodyHash[:]))

	parsedDestURL, err := url.Parse(destinationURL)
	if err != nil {
		// Counter for URL parse failures
		// use error code for URL MAC
	} else {
		urlHash := sha256.Sum256([]byte(parsedDestURL.String()))
		glog.Infof("URL hash is %s", base64.RawURLEncoding.EncodeToString(urlHash[:]))
	}

	return &authenticatedConnectionSignature{signatureMessage: "foo"}, nil
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
