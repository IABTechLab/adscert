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
	"time"

	"github.com/spf13/cobra"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

// testnoopCmd represents the test sign command
var (
	testnoopParams = &testnoopParameters{}

	testnoopCmd = &cobra.Command{
		Use:   "testnoop",
		Short: "Send a no-operations request to grpc server.",
		Run: func(cmd *cobra.Command, args []string) {
			sendNoOp(testnoopParams)
		},
	}
)

type testnoopParameters struct {
	url            string
	serverAddress  string
	body           string
	signingTimeout time.Duration
}

func init() {
	rootCmd.AddCommand(testnoopCmd)

	testnoopCmd.Flags().StringVar(&testnoopParams.url, "url", "", "URL to invoke")
	testnoopCmd.Flags().StringVar(&testnoopParams.serverAddress, "server_address", "localhost:3000", "address of grpc server")
	testnoopCmd.Flags().StringVar(&testnoopParams.body, "body", "", "POST request body")
	testnoopCmd.Flags().DurationVar(&testnoopParams.signingTimeout, "signing_timeout", 5*time.Millisecond, "Specifies how long this client will wait for signing to finish before abandoning.")
}

func sendNoOp(testnoopParams *testnoopParameters) *api.AuthenticatedConnectionSignatureResponse {

	// Establish the gRPC connection that the client will use to connect to the
	// signatory server.  This basic example uses unauthenticated connections
	// which should not be used in a production environment.
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(testnoopParams.serverAddress, opts...)
	if err != nil {
		logger.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Create a reusable Signatory Client that provides a lightweight wrapper
	// around the RPC client stub.  This code performs some basic request
	// timeout and error handling logic.
	clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: testnoopParams.signingTimeout}
	signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

	// The RequestInfo proto contains details about the individual ad request
	// being signed.  A SetRequestInfo helper function derives a hash of the
	// destination URL and body, setting these value on the RequestInfo message.
	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, testnoopParams.url, []byte(testnoopParams.body))

	// Request the signature.
	logger.Infof("signing request for url: %v", testnoopParams.url)
	signatureResponse, err := signatoryClient.NoOperationResponse(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
		})
	if err != nil {
		logger.Warningf("error during noop request: %v", err)
	}

	// In most circumstances a signatureResponse will be returned which includes
	// detals about the successful or failed signature attempt.
	if signatureResponse != nil {
		logger.Infof("signature response:\n%s", prototext.Format(signatureResponse))
	} else {
		logger.Warningf("signature response is missing")
	}
	return signatureResponse
}
