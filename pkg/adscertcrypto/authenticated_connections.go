package adscertcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

type AuthenticatedConnectionSigningPackage struct {
	InvocationHostname string
	Timestamp          string // 2021-04-18T23:59:59
	Nonce              string // ABCDEFGHIJKL

	URLHash  [32]byte
	BodyHash [32]byte
}

type ScopedHashParams struct {
	InvocationURL string
	Body          []byte
}

func (r *AuthenticatedConnectionSigningPackage) CalculateScopedHashes(params ScopedHashParams) {
	scope := fmt.Sprintf("%s/%s/%s", r.Timestamp, r.Nonce, r.InvocationHostname)
	h := hmac.New(sha256.New, []byte(scope))
	copy(r.URLHash[:], h.Sum([]byte(params.InvocationURL)))
	copy(r.BodyHash[:], h.Sum([]byte(params.Body)))
}

type AuthenticatedConnectionSignatureResponse struct {
	SignatureMessage []string
}
