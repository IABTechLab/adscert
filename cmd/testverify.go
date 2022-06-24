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
		Short: "Given a URL (via same flags as the testsign command) and some signature received (via a flag), validate the signature",
		Run: func(cmd *cobra.Command, args []string) {
			// fmt.Printf("generated signature: %d\n", signUrl((*testverifyParams).url))
			verifyRequest(testverifyParams)
		},
	}
)

type testverifyParameters struct {
	origin string
	// signatureLogFile string
	destinationURL   string
	serverAddress    string
	body             string
	verifyingTimeout time.Duration
	signatureMessage string
}

func init() {
	rootCmd.AddCommand(testverifyCmd)

	// testverifyCmd.Flags().StringVar(&testverifyParams.origin, "origin", "", "ads.cert Call Sign domain for the sending party")
	// testverifyCmd.Flags().StringVar(&testverifyParams.signatureLogFile, "signature_log_file", "", "(optional) write signature and hashes to file for offline verification")
	testverifyCmd.Flags().StringVar(&testverifyParams.signatureMessage, "signatureMessage", "", "signature message to verify")
	testverifyCmd.Flags().StringVar(&testverifyParams.destinationURL, "url", "", "URL to invoke")
	testverifyCmd.Flags().StringVar(&testverifyParams.serverAddress, "server_address", "localhost:3000", "address of grpc server")
	testverifyCmd.Flags().StringVar(&testverifyParams.body, "body", "", "POST request body")
	testverifyCmd.Flags().DurationVar(&testverifyParams.verifyingTimeout, "verifying_timeout", 5*time.Millisecond, "Specifies how long this client will wait for signing to finish before abandoning.")
}

func verifyRequest(testverifyParams *testverifyParameters) {
	{

		// Establish the gRPC connection that the client will use to connect to the
		// signatory server.  This basic example uses unauthenticated connections
		// which should not be used in a production environment.
		opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		conn, err := grpc.Dial(testsignParams.serverAddress, opts...)
		if err != nil {
			logger.Fatalf("Failed to dial: %v", err)
		}
		defer conn.Close()
	
		// Optional: performs a health check against the server before actually
		// trying to invoke the signatory service.
	
		// performOptionalHealthCheckRPC(conn)
	
		// Create a reusable Signatory Client that provides a lightweight wrapper
		// around the RPC client stub.  This code performs some basic request
		// timeout and error handling logic.
		clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: testsignParams.signingTimeout}
		signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)
	
		// The RequestInfo proto contains details about the individual ad request
		// being signed.  A SetRequestInfo helper function derives a hash of the
		// destination URL and body, setting these value on the RequestInfo message.
		signatureHeaders := testverifyParams.signatureMessage

		reqInfo := &api.RequestInfo{}
		signatory.SetRequestInfo(reqInfo, testverifyParams.destinationURL, body)
		signatory.SetRequestSignatures(reqInfo, signatureHeaders)
	
		// Request the signature.
		logger.Infof("verifying request for url: %v", testsignParams.destinationURL)
		verificationResponse, err := signatoryClient.VerifyAuthenticatedConnection(
			&api.AuthenticatedConnectionVerificationRequest{
				RequestInfo: reqInfo,
			})
		if err != nil {
			logger.Warningf("unable to verify message: %v", err)
		}
	
		// In most circumstances a verificationResponse will be returned which includes
		// detals about the successful or failed signature attempt.
		if verificationResponse != nil {
			logger.Infof("verification response:\n%s", prototext.Format(verificationResponse))
		} else {
			logger.Warningf("verification response is missing")
		}
	}
