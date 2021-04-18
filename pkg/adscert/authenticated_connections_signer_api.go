package adscert

// AuthenticatedConnectionsSigner generates a signature intended for the
// specified party over the specified message.
type AuthenticatedConnectionsSigner interface {
	SignAuthenticatedConnection(params SignAuthenticatedConnectionParams) (AuthenticatedConnectionSignature, error)
}

type SignAuthenticatedConnectionParams struct {
	DestinationURL string
	RequestBody    []byte
}

// AuthenticatedConnectionSignature represents a signature conforming to the
// ads.cert Authenticated Connections specification.
type AuthenticatedConnectionSignature struct {
	SignatureMessage string
}
