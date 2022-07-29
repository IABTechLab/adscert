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
	"github.com/spf13/cobra"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

// testverifyCmd represents the test verify command
var (
	testverifyParams = &testverifyParameters{}

	testverifyCmd = &cobra.Command{
		Use:   "testverify",
		Short: "Given a URL (via same flags as the testsign command) and some signature received (via a flag), validate the signature",
		Run: func(cmd *cobra.Command, args []string) {
			verifyRequest(testverifyParams)
		},
	}
)

type testverifyParameters struct {
	destinationURL   string
	serverAddress    string
	body             string
	verifyingTimeout time.Duration
	signatureMessage string
}

func init() {
	rootCmd.AddCommand(testverifyCmd)

	testverifyCmd.Flags().StringVar(&testverifyParams.signatureMessage, "signatureMessage", "", "signature message to verify")
	testverifyCmd.Flags().StringVar(&testverifyParams.destinationURL, "url", "", "URL to verify")
	testverifyCmd.Flags().StringVar(&testverifyParams.serverAddress, "server_address", "localhost:3000", "address of grpc server")
	testverifyCmd.Flags().StringVar(&testverifyParams.body, "body", "", "POST request body")
	testverifyCmd.Flags().DurationVar(&testverifyParams.verifyingTimeout, "verifying_timeout", 5*time.Millisecond, "Specifies how long this client will wait for verification to finish before abandoning.")
}

func verifyRequest(testverifyParams *testverifyParameters) {
	{

		// Establish the gRPC connection that the client will use to connect to the
		// signatory server.  This basic example uses unauthenticated connections
		// which should not be used in a production environment.
		opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		conn, err := grpc.Dial(testverifyParams.serverAddress, opts...)
		if err != nil {
			logger.Fatalf("Failed to dial: %v", err)
		}
		defer conn.Close()

		// Create a reusable Signatory Client that provides a lightweight wrapper
		// around the RPC client stub.  This code performs some basic request
		// timeout and error handling logic.
		clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: testverifyParams.verifyingTimeout}
		signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

		// The RequestInfo proto contains details about the individual ad request
		// being verified.  A SetRequestInfo helper function derives a hash of the
		// destination URL and body, and sets the hash and the signature message on the RequestInfo message.
		signatureHeaders := []string{testverifyParams.signatureMessage}

		reqInfo := &api.RequestInfo{}
		signatory.SetRequestInfo(reqInfo, testverifyParams.destinationURL, []byte(testverifyParams.body))
		signatory.SetRequestSignatures(reqInfo, signatureHeaders)

		// Request the verification.
		logger.Infof("verifying request for url: %v", testverifyParams.destinationURL)
		verificationResponse, err := signatoryClient.VerifyAuthenticatedConnection(
			&api.AuthenticatedConnectionVerificationRequest{
				RequestInfo: []*api.RequestInfo{reqInfo},
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
}
