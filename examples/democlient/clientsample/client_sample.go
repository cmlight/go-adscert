package clientsample

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/cmlight/go-adscert/pkg/adscert"
	"github.com/golang/glog"
)

type DemoClient struct {
	Signer adscert.AuthenticatedConnectionsSigner

	Method         string
	DestinationURL string
	Body           []byte

	ActuallySendRequest bool
	Ticker              *time.Ticker
}

func (c *DemoClient) StartRequestLoop() {
	c.initiateRequest()
	for range c.Ticker.C {
		if err := c.initiateRequest(); err != nil {
			glog.Warningf("Error sending request: %v", err)
		}
	}
}

func (c *DemoClient) initiateRequest() error {
	req, err := http.NewRequest(c.Method, c.DestinationURL, bytes.NewReader(c.Body))
	if err != nil {
		return fmt.Errorf("error building HTTP request: %v", err)
	}

	signature, err := c.Signer.SignAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL: c.DestinationURL,
			RequestBody:    c.Body,
		})
	if err != nil {
		glog.Warningf("unable to sign message (continuing...): %v", err)
	}

	req.Header["X-Ads-Cert-Auth"] = signature.SignatureMessages

	glog.Infof("Requesting URL %s %s with headers %v", req.Method, req.URL, req.Header)

	if c.ActuallySendRequest {
		glog.Info("Sendng request...")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("error sending HTTP request: %v", err)
		}

		scanner := bufio.NewScanner(resp.Body)
		for i := 0; scanner.Scan() && i < 5; i++ {
			fmt.Println(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading response: %v", err)
		}
	} else {
		glog.Info("(Request not actually sent)")
	}
	return nil
}
