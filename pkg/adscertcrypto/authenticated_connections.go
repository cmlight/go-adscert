package adscertcrypto

type AuthenticatedConnectionSignatureRequest struct {
	InvocationHostname string
	URLHash            [32]byte
	BodyHash           [32]byte
}

type AuthenticatedConnectionSignatureResponse struct {
	SignatureMessage string
}
