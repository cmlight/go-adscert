package adscert

import "github.com/cmlight/go-adscert/pkg/adscertcrypto"

// AuthenticatedConnectionsSigner generates a signature intended for the
// specified party over the specified message.
type AuthenticatedConnectionsSigner interface {
	SignAuthenticatedConnection(params SignAuthenticatedConnectionParams) (AuthenticatedConnectionSignature, error)
}

// NewAuthenticatedConnectionsSigner creates a new signer instance for creating
// ads.cert Authenticated Connections signatures.
func NewAuthenticatedConnectionsSigner(adscertcrypto adscertcrypto.AdsCertCrypto) AuthenticatedConnectionsSigner {
	return &authenticatedConnectionsSigner{}
}

// SignAuthenticatedConnectionParams captures parameters for the
// SignAuthenticatedConnection operation.
type SignAuthenticatedConnectionParams struct {
	DestinationURL string
	RequestBody    []byte
}

// AuthenticatedConnectionSignature represents a signature conforming to the
// ads.cert Authenticated Connections specification.
type AuthenticatedConnectionSignature struct {
	SignatureMessage string
}
