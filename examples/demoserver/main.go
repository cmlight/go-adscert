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
	hostCallsign = flag.String("host_callsign", "", "ads.cert callsign for the originating party")
)

func main() {
	flag.Parse()

	glog.Info("Starting demo server.")

	demoServer := &serversample.DemoServer{
		Signer: adscert.NewAuthenticatedConnectionsSigner(
			adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*hostCallsign, "keyplaceholder")),
	}
	http.HandleFunc("/request", demoServer.HandleRequest)
	http.ListenAndServe(":8090", nil)
}
