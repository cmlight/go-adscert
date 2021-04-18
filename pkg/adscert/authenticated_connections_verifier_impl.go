package adscert

type authenticatedConnectionsVerifier struct{}

func (c *authenticatedConnectionsVerifier) VerifyAuthenticatedConnection(
	destinationURL string,
	body []byte,
	signature AuthenticatedConnectionSignature) (AuthenticatedConnectionVerification, error) {
	// TODO: implement this.
	return nil, nil
}
