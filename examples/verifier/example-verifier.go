package main

import (
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
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

	demoServer := &DemoServer{
		Signer: adscert.NewAuthenticatedConnectionsSigner(
			adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*hostCallsign, privateKeysBase64, *useFakeKeyGeneratingDNS), crypto_rand.Reader),
	}
	http.HandleFunc("/request", demoServer.HandleRequest)
	http.ListenAndServe(":8090", nil)
}

type DemoServer struct {
	Signer adscert.AuthenticatedConnectionsSigner
}

func (s *DemoServer) HandleRequest(w http.ResponseWriter, req *http.Request) {
	signatureHeaders := req.Header["X-Ads-Cert-Auth"]

	// Make a copy of the URL struct so that we can reconstruct what the client sent.
	// Obtaining the invoked hostname may be impacted by reverse proxy servers, load balancing
	// software, CDNs, or other middleware solutions, so some experimentation may be needed
	// to customize URL reconstruction within your environment.
	reconstructedURL := *req.URL
	reconstructedURL.Scheme = "http" // For testing only: production systems would use https.
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
