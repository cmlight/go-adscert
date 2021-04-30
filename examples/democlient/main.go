package main

import (
	"flag"
	"time"

	"github.com/cmlight/go-adscert/examples/democlient/clientsample"
	"github.com/cmlight/go-adscert/pkg/adscert"
	"github.com/cmlight/go-adscert/pkg/adscertcrypto"
	"github.com/golang/glog"
)

var (
	method         = flag.String("http_method", "GET", "HTTP method, 'GET' or 'POST'")
	destinationURL = flag.String("url", "https://google.com/gen_204", "URL to invoke")
	body           = flag.String("body", "", "POST request body")
	sendRequests   = flag.Bool("send_requests", false, "Actually invoke the web server")
	frequency      = flag.Duration("frequency", 10*time.Second, "Frequency to invoke the specified URL")

	originCallsign = flag.String("origin_callsign", "", "ads.cert callsign for the originating party")

	useFakeKeyGeneratingDNS = flag.Bool("use_fake_key_generating_dns_for_testing", false,
		"When enabled, this code skips performing real DNS lookups and instead simulates DNS-based keys by generating a key pair based on the domain name.")
)

func main() {
	flag.Parse()

	glog.Info("Starting demo client.")

	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*originCallsign)

	demoClient := clientsample.DemoClient{
		Signer: adscert.NewAuthenticatedConnectionsSigner(
			adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*originCallsign, privateKeysBase64, *useFakeKeyGeneratingDNS)),

		Method:         *method,
		DestinationURL: *destinationURL,
		Body:           []byte(*body),

		ActuallySendRequest: *sendRequests,
		Ticker:              time.NewTicker(*frequency),
	}
	demoClient.StartRequestLoop()
}
