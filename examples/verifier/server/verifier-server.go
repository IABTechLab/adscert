package main

import (
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	hostCallsign            = flag.String("host_callsign", "", "ads.cert callsign for the originating party")
	useFakeKeyGeneratingDNS = flag.Bool("use_fake_key_generating_dns_for_testing", false,
		"When enabled, this code skips performing real DNS lookups and instead simulates DNS-based keys by generating a key pair based on the domain name.")
)

func main() {
	flag.Parse()

	logger.Infof("Starting demo server.")

	privateKeysBase64 := signatory.GenerateFakePrivateKeysForTesting(*hostCallsign)

	var dnsResolver discovery.DNSResolver
	if *useFakeKeyGeneratingDNS {
		dnsResolver = discovery.NewFakeDnsResolver()
	} else {
		dnsResolver = discovery.NewRealDnsResolver()
	}

	demoServer := &DemoServer{
		Signatory: signatory.NewLocalAuthenticatedConnectionsSignatory(*hostCallsign, crypto_rand.Reader, clock.New(), dnsResolver, privateKeysBase64),
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

	// TODO: include this in automatic url parsing to handle hostnames without scheme/protocol

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

	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, reconstructedURL.String(), body)

	verification, err := s.Signatory.VerifyAuthenticatedConnection(
		&api.AuthenticatedConnectionVerificationRequest{
			RequestInfo:      reqInfo,
			SignatureMessage: signatureHeaders,
		})

	fmt.Fprintf(w, "You invoked %s with X-Ads-Cert-Auth headers %v and verification body:%v URL:%v\n", reconstructedURL.String(), req.Header["X-Ads-Cert-Auth"], verification.BodyValid, verification.UrlValid)
}
