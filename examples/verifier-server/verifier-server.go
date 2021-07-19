package main

import (
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	origin = flag.String("origin", "", "ads.cert identity domain for the receiving party")
)

func main() {
	flag.Parse()

	logger.Infof("Starting demo server.")

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(*origin)

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		*origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(30*time.Second), // domain check interval
		time.Duration(30*time.Second), // domain renewal interval
		base64PrivateKeys)

	demoServer := &DemoServer{
		Signatory: signatoryApi,
	}

	http.HandleFunc("/request", demoServer.HandleRequest)
	http.Handle("/metrics", promhttp.HandlerFor(metrics.GetAdscertMetricsRegistry(), promhttp.HandlerOpts{}))
	http.ListenAndServe(":8090", nil)
}

type DemoServer struct {
	Signatory signatory.AuthenticatedConnectionsSignatory
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
		logger.Errorf("failed to read request: %s", err)
		req.Response.Status = "500 Server Error"
		return
	}

	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, reconstructedURL.String(), body)
	signatory.SetRequestSignatures(reqInfo, signatureHeaders)

	verification, err := s.Signatory.VerifyAuthenticatedConnection(&api.AuthenticatedConnectionVerificationRequest{RequestInfo: reqInfo})
	if err != nil {
		logger.Errorf("unable to verify message: %s", err)
	}

	fmt.Fprintf(w, "You invoked %s with X-Ads-Cert-Auth headers %v and verification body:%v URL:%v\n", reconstructedURL.String(), req.Header["X-Ads-Cert-Auth"], verification.BodyValid, verification.UrlValid)
}
