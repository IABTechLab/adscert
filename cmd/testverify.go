/*
Copyright © 2022 IAB Technology Laboratory, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// testverifyCmd represents the signatory command
var (
	testverifyParams = &testverifyParameters{}

	testverifyCmd = &cobra.Command{
		Use:   "testverify",
		Short: "Given a URL (via same flags as the testverify command) and some signature received (via a flag), validate the signature",
		Run: func(cmd *cobra.Command, args []string) {
			// fmt.Printf("generated signature: %d\n", signUrl((*testverifyParams).url))
			verifyRequest(testverifyParams)
		},
	}
)

type testverifyParameters struct {
	origin string
	// signatureLogFile string
}

func init() {
	rootCmd.AddCommand(testverifyCmd)

	testverifyCmd.Flags().StringVar(&testverifyParams.origin, "origin", "", "ads.cert Call Sign domain for the receiving party")
	// testverifyCmd.Flags().StringVar(&testverifyParams.signatureLogFile, "signature_log_file", "", "(optional) write signature and hashes to file for offline verification")
}

func verifyRequest(testverifyParams *testverifyParameters) {
	logger.Infof("Starting demo server.")

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(testverifyParams.origin)

	var signatureFileLogger *log.Logger
	// if testverifyParams.signatureLogFile != "" {
	// 	file, err := os.OpenFile(testverifyParams.signatureLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	// 	if err != nil {
	// 		logger.Fatalf("Error opening signature log file %q: %v", testverifyParams.signatureLogFile, err)
	// 	}
	// 	defer file.Close()

	// 	signatureFileLogger = log.New(file, "" /*=prefix*/, 0 /*=flag=*/)
	// }

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		testverifyParams.origin,
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
