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
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

// testsignCmd represents the test sign command
var (
	testsignParams = &testsignParameters{}

	testsignCmd = &cobra.Command{
		Use:   "testsign",
		Short: "Given a URL to invoke (and optionally, a request body) generate a signature.",
		Run: func(cmd *cobra.Command, args []string) {
			signRequest(testsignParams)
		},
	}
)

type testsignParameters struct {
	url            string
	serverAddress  string
	body           string
	signingTimeout time.Duration
}

func init() {
	rootCmd.AddCommand(testsignCmd)

	testsignCmd.Flags().StringVar(&testsignParams.url, "url", "", "URL to invoke")
	testsignCmd.Flags().StringVar(&testsignParams.serverAddress, "server_address", "localhost:3000", "address of grpc server")
	testsignCmd.Flags().StringVar(&testsignParams.body, "body", "", "POST request body")
	testsignCmd.Flags().DurationVar(&testsignParams.signingTimeout, "signing_timeout", 5*time.Millisecond, "Specifies how long this client will wait for signing to finish before abandoning.")
}

func signRequest(testsignParams *testsignParameters) error {

	// Establish the gRPC connection that the client will use to connect to the
	// signatory server.  This basic example uses unauthenticated connections
	// which should not be used in a production environment.
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(testsignParams.serverAddress, opts...)
	if err != nil {
		logger.Warningf("Failed to dial: %v", err)
		return fmt.Errorf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Create a reusable Signatory Client that provides a lightweight wrapper
	// around the RPC client stub.  This code performs some basic request
	// timeout and error handling logic.
	clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: testsignParams.signingTimeout}
	signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

	// The RequestInfo proto contains details about the individual ad request
	// being signed.  A SetRequestInfo helper function derives a hash of the
	// destination URL and body, setting these value on the RequestInfo message.
	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, testsignParams.url, []byte(testsignParams.body))

	// Request the signature.
	logger.Infof("signing request for url: %v", testsignParams.url)
	signatureResponse, err := signatoryClient.SignAuthenticatedConnection(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
		})
	if err != nil {
		logger.Warningf("unable to sign message: %v", err)
	}

	// In most circumstances a signatureResponse will be returned which includes
	// detals about the successful or failed signature attempt.
	if signatureResponse != nil {
		logger.Infof("signature response:\n%s", prototext.Format(signatureResponse))
		if signatureResponse.SignatureOperationStatus ==
			api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_SIGNATORY_INTERNAL_ERROR {
			return fmt.Errorf("no records for invoked url")
		}
	} else {
		logger.Warningf("signature response is missing")
		return fmt.Errorf("signature response is missing")
	}
	return nil
}
