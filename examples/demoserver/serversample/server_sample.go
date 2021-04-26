package serversample

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cmlight/go-adscert/pkg/adscert"
)

type DemoServer struct {
	Signer adscert.AuthenticatedConnectionsSigner
}

func (s *DemoServer) HandleRequest(w http.ResponseWriter, req *http.Request) {
	signatureHeaders := req.Header["X-Ads-Cert-Auth"]

	// Make a copy of the URL struct so that we can reconstruct what the client sent.
	reconstructedURL := *req.URL
	reconstructedURL.Scheme = "http" // TODO: Fix so that this can handle HTTPS too.
	reconstructedURL.Host = req.Host

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		req.Response.Status = "500 Server Error"
		return
	}

	verification, err := s.Signer.VerifyAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL:           reconstructedURL.String(),
			RequestBody:              body,
			SignatureMessageToVerify: signatureHeaders,
		})

	fmt.Fprintf(w, "You invoked %s with headers %v and verification %v %v\n", reconstructedURL.String(), req.Header, verification.BodyValid, verification.URLValid)
}
