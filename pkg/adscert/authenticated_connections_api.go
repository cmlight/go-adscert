package adscert

// AuthenticatedConnectionsManager provides a thread-safe, singleton instance
// of the logic for signing and verifying requests conforming to the ads.cert
// Authenticated Connections protocol.
type AuthenticatedConnectionsManager interface {
	AuthenticatedConnectionsSigner() AuthenticatedConnectionsSigner
	AuthenticatedConnectionsVerifier() AuthenticatedConnectionsVerifier
}

// AuthenticatedConnectionsSigner generates a signature intended for the
// specified party over the specified message.
type AuthenticatedConnectionsSigner interface {
	SignAuthenticatedConnection(destinationURL string, body []byte) (AuthenticatedConnectionSignature, error)
}

// AuthenticatedConnectionsVerifier verifies a signature purported to be from
// the specified party over the specified message.
type AuthenticatedConnectionsVerifier interface {
	VerifyAuthenticatedConnection(destinationURL string, body []byte, signature AuthenticatedConnectionSignature) (AuthenticatedConnectionVerification, error)
}

// AuthenticatedConnectionSignature represents a signature conforming to the
// ads.cert Authenticated Connections specification.
type AuthenticatedConnectionSignature interface {
	String() string
}

// AuthenticatedConnectionVerification captures the results of verifying a
// signature against the ads.cert Authenticated Connections specification
// requirements.
type AuthenticatedConnectionVerification interface{}
