package adscert_test

import (
	"fmt"
	"log"

	"github.com/cmlight/go-adscert/pkg/adscert"
	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
)

func ExampleAuthenticatedConnectionsSigner_SignAuthenticatedConnection() {
	signatory := adscertcrypto.NewLocalAuthenticatedConnectionsSignatory("origin-signer.com", "a1b2c3")
	signer := adscert.NewAuthenticatedConnectionsSigner(signatory)

	signatory.SynchronizeForTesting("destination-verifier.com")

	// Determine the request parameters to sign.
	destinationURL := "https://ads.destination-verifier.com/request-ads"
	body := []byte("{'id': '12345'}")

	signature, err := signer.SignAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL: destinationURL,
			RequestBody:    body,
		})
	if err != nil {
		log.Fatal("unable to sign message: ", err)
	}

	fmt.Print("Signature passed via X-Ads-Cert-Auth: ", signature.SignatureMessages)
	// Output: Signature passed via X-Ads-Cert-Auth: [from=origin-signer.com&invoking=example.com&status=0]

}

func ExampleAuthenticatedConnectionsSigner_VerifyAuthenticatedConnection() {
	signatory := adscertcrypto.NewLocalAuthenticatedConnectionsSignatory("destination-verifier.com", "w1x2y3")
	signer := adscert.NewAuthenticatedConnectionsSigner(signatory)

	signatory.SynchronizeForTesting("origin-signer.com")

	// Determine the request parameters to sign.
	// Destination URL must be assembled by application based on path, HTTP Host header.
	// TODO: assemble sample code to show this based on HTTP package.
	destinationURL := "https://ads.origin-signer.com/request-ads"
	body := []byte("{'id': '12345'}")
	messageToVerify := "from=origin-signer.com&invoking=origin-signer.com&status=0; sigb=x&sigu=y"

	verification, err := signer.VerifyAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL:           destinationURL,
			RequestBody:              body,
			SignatureMessageToVerify: []string{messageToVerify},
		})
	if err != nil {
		log.Fatal("unable to verify message: ", err)
	}

	fmt.Printf("Signature verified? %v %v", verification.BodyValid, verification.URLValid)
	// Output: Signature verified? true, true
}
