package main

import (
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/cmlight/go-adscert/pkg/adscertcounterparty"
	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
)

var (
	domainForFakeKeys = flag.String("calculate_fake_keys_for_domain", "",
		"Domain name (e.g. 'example.com') to use for fake key generation (private key is just a SHA-256 hash of domain name.)")
)

func main() {
	flag.Parse()

	if *domainForFakeKeys != "" {
		publicKey, privateKey := adscertcrypto.GenerateFakeKeyPairFromDomainNameForTesting(*domainForFakeKeys)
		fmt.Println("These are insecure keys and should not be used for production authentication purposes.")
		fmt.Printf("FAKE FAKE FAKE public key for testing  %s FAKE FAKE FAKE\n", base64.RawURLEncoding.EncodeToString(publicKey[:]))
		fmt.Printf("FAKE FAKE FAKE private key for testing %s FAKE FAKE FAKE\n", base64.RawURLEncoding.EncodeToString(privateKey[:]))
	} else {
		publicKey, privateKey, err := adscertcounterparty.GenerateKeyPair()
		if err != nil {
			fmt.Printf("Error: failed to generate key pair: %v", err)
		}
		fmt.Println("Randomly generated key pair")
		fmt.Printf("Public key:  %s\n", publicKey)
		fmt.Printf("Private key: %s\n", privateKey)
	}

}
