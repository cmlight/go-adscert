package main

import (
	"flag"
	"net/http"

	"github.com/cmlight/go-adscert/examples/demoserver/serversample"
	"github.com/cmlight/go-adscert/pkg/adscert"
	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"github.com/golang/glog"
)

var (
	hostCallsign            = flag.String("host_callsign", "", "ads.cert callsign for the originating party")
	useFakeKeyGeneratingDNS = flag.Bool("use_fake_key_generating_dns_for_testing", false,
		"When enabled, this code skips performing real DNS lookups and instead simulates DNS-based keys by generating a key pair based on the domain name.")
)

func main() {
	flag.Parse()

	glog.Info("Starting demo server.")

	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*hostCallsign)

	demoServer := &serversample.DemoServer{
		Signer: adscert.NewAuthenticatedConnectionsSigner(
			adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*hostCallsign, privateKeysBase64, *useFakeKeyGeneratingDNS)),
	}
	http.HandleFunc("/request", demoServer.HandleRequest)
	http.ListenAndServe(":8090", nil)
}
