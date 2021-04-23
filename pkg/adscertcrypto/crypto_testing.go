package adscertcrypto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/cmlight/go-adscert/pkg/adscertcounterparty"
	"golang.org/x/crypto/curve25519"
)

func GenerateFakeKeyPairFromDomainNameForTesting(adscertCallsign string) ([32]byte, [32]byte) {
	privateKey := sha256.Sum256([]byte(adscertCallsign))
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey, privateKey
}

type keyGeneratingDNSResolver struct{}

func (r *keyGeneratingDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	publicKey, _ := GenerateFakeKeyPairFromDomainNameForTesting(name)
	return []string{base64.RawURLEncoding.EncodeToString(publicKey[:])}, nil
}

func NewFakeKeyGeneratingDnsResolver() adscertcounterparty.DNSResolver {
	return &keyGeneratingDNSResolver{}
}
