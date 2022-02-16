package main

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	origin           = flag.String("origin", "", "ads.cert Call Sign domain for the receiving party")
	signatureLogFile = flag.String("signature_log_file", "", "(optional) write signature and hashes to file for offline verification")
)

func main() {
	flag.Parse()

	logger.Infof("Starting demo server.")

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(*origin)

	var signatureFileLogger *log.Logger
	if *signatureLogFile != "" {
		file, err := os.OpenFile(*signatureLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logger.Fatalf("Error opening signature log file %q: %v", *signatureLogFile, err)
		}
		defer file.Close()

		signatureFileLogger = log.New(file, "" /*=prefix*/, 0 /*=flag=*/)
	}

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		"info",
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

		SignatureFileLogger: signatureFileLogger,
	}

	http.HandleFunc("/request", demoServer.HandleRequest)
	http.Handle("/metrics", promhttp.HandlerFor(metrics.GetAdscertMetricsRegistry(), promhttp.HandlerOpts{}))
	http.ListenAndServe(":8090", nil)
}

type DemoServer struct {
	Signatory signatory.AuthenticatedConnectionsSignatory

	SignatureFileLogger *log.Logger
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

	if s.SignatureFileLogger != nil {
		s.SignatureFileLogger.Printf("%s,%s,%s,%s",
			reqInfo.BodyHash,
			reqInfo.SignatureInfo[0],
			base64.StdEncoding.EncodeToString(reqInfo.BodyHash),
			base64.StdEncoding.EncodeToString(reqInfo.UrlHash))
	}

	verificationRequest := &api.AuthenticatedConnectionVerificationRequest{RequestInfo: []*api.RequestInfo{reqInfo}}
	verificationResponse, err := s.Signatory.VerifyAuthenticatedConnection(verificationRequest)
	if err != nil {
		logger.Errorf("unable to verify message: %s", err)
	}

	var bodyValid, urlValid bool
	for _, decode := range verificationResponse.VerificationInfo[0].SignatureDecodeStatus {
		if decode == api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID {
			bodyValid = true
			urlValid = true
			break
		} else if decode == api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_VALID {
			bodyValid = true
			break
		}
	}

	fmt.Fprintf(w, "You invoked %s with X-Ads-Cert-Auth headers %v and verification body:%v URL:%v\n", reconstructedURL.String(), req.Header["X-Ads-Cert-Auth"], bodyValid, urlValid)
}
