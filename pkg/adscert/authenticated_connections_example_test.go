package adscert_test

import (
	"fmt"
	"log"

	"github.com/cmlight/go-adscert/pkg/adscert"
	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
)

func ExampleAuthenticatedConnectionsSigner_SignAuthenticatedConnection() {
	signer := adscert.NewAuthenticatedConnectionsSigner(
		adscertcrypto.NewLocalAuthenticatedConnectionsSignatory("origin-signer.com", "a1b2c3"))

	// Determine the request parameters to sign.
	destinationURL := "https://ads.foo.com/request-ads"
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
	// Output: Signature passed via X-Ads-Cert-Auth: [foo]

}

func ExampleAuthenticatedConnectionsSigner_VerifyAuthenticatedConnection() {
	signer := adscert.NewAuthenticatedConnectionsSigner(
		adscertcrypto.NewLocalAuthenticatedConnectionsSignatory("destination-verifier.com", "w1x2y3"))

	// Determine the request parameters to sign.
	// Destination URL must be assembled by application based on path, HTTP Host header.
	// TODO: assemble sample code to show this based on HTTP package.
	destinationURL := "https://ads.example.com/request-ads"
	body := []byte("{'id': '12345'}")
	messageToVerify := "[foo]"

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
