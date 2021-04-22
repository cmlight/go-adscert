package adscertcrypto

type RequestInfo struct {
	InvocationHostname string
	URLHash            [32]byte
	BodyHash           [32]byte
}

type AuthenticatedConnectionSigningPackage struct {
	Timestamp string // 2021-04-18T23:59:59
	Nonce     string // ABCDEFGHIJKL

	RequestInfo RequestInfo
}

type AuthenticatedConnectionSignatureResponse struct {
	SignatureMessages []string
}

type AuthenticatedConnectionVerificationPackage struct {
	RequestInfo      RequestInfo
	SignatureMessage string
}

type AuthenticatedConnectionVerificationResponse struct {
	// TODO: Fill this out with something better.
	Valid bool
}
