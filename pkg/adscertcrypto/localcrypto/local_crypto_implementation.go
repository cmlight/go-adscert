package localcrypto

import (
	crypto_rand "crypto/rand"

	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"github.com/cmlight/go-adscert/pkg/adscertcrypto/localcrypto/internal"
)

// NewLocalAdsCertCrypto creates an AdsCertCrypto instance where all keys are
// managed in the same process memory as the app utilizing this API.
func NewLocalAdsCertCrypto() adscertcrypto.AdsCertCrypto {
	return internal.NewAdsCertCryptoInternal(crypto_rand.Reader)
}
