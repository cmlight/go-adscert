package adscert_test

import (
	"fmt"
	"log"

	"github.com/cmlight/go-adscert/pkg/adscert"
	"github.com/cmlight/go-adscert/pkg/adscertcrypto/localcrypto"
)

func Example() {
	// Initialize a singleton AdsCertCrypto instance for the application.
	// adsCertCrypto := localcrypto.NewLocalAdsCertCrypto()
	signer := adscert.NewAuthenticatedConnectionsSigner(
		localcrypto.NewLocalAdsCertCrypto())

	// Determine the request parameters to sign.
	destinationURL := "https://ads.example.com/request-ads"
	body := []byte("{'id': '12345'}")

	signature, err := signer.SignAuthenticatedConnection(
		adscert.SignAuthenticatedConnectionParams{
			DestinationURL: destinationURL,
			RequestBody:    body,
		})
	if err != nil {
		log.Fatal("unable to sign message: ", err)
	}

	fmt.Print("Signature passed via X-Ads-Cert-Auth: ", signature.SignatureMessage)
	// Output: Signature passed via X-Ads-Cert-Auth: [foo]

}
