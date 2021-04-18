package adscert_test

import (
	"fmt"
	"log"

	"github.com/cmlight/go-adscert/pkg/adscert"
)

func Example() {
	// Initialize a singleton AdsCertCrypto instance for the application.
	// adsCertCrypto := localcrypto.NewLocalAdsCertCrypto()
	authedConnections := adscert.NewAuthenticatedConnectionsManager()

	// Determine the request parameters to sign.
	destinationURL := "https://ads.example.com/request-ads"
	body := []byte("{'id': '12345'}")

	signer := authedConnections.AuthenticatedConnectionsSigner()
	signature, err := signer.SignAuthenticatedConnection(destinationURL, body)
	if err != nil {
		log.Fatal("unable to sign message: ", err)
	}

	signatureMessage := signature.String()
	fmt.Print("Signature passed via X-Ads-Cert-Auth: ", signatureMessage)
	// Output: Signature passed via X-Ads-Cert-Auth: foo

}
