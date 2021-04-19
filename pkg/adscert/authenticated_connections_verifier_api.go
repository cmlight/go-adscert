package adscert

// AuthenticatedConnectionsVerifier verifies a signature purported to be from
// the specified party over the specified message.
type AuthenticatedConnectionsVerifier interface {
	VerifyAuthenticatedConnection(destinationURL string, body []byte, signature AuthenticatedConnectionSignature) (AuthenticatedConnectionVerification, error)
}

// VerifyAuthenticatedConnectionParams provides parameters for verifying an
// Authenticated Connection signature for a given HTTP request.
type VerifyAuthenticatedConnectionParams struct {
	DestinationURL   string
	RequestBody      []byte
	SignatureMessage []string
}

// AuthenticatedConnectionVerification captures the results of verifying a
// signature against the ads.cert Authenticated Connections specification
// requirements.
type AuthenticatedConnectionVerification interface{}
