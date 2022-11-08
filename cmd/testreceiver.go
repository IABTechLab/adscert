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
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

// testreceiverCmd represents the test receivergit command
var (
	testreceiverParams = &testreceiverParameters{}

	testreceiverCmd = &cobra.Command{
		Use:   "testreceiver",
		Short: "Run a simple local web server that will receive and verify requests",
		Run: func(cmd *cobra.Command, args []string) {
			startServer(testreceiverParams)
		},
	}
)

type testreceiverParameters struct {
	serverPort       string
	verifierAddress  string
	verifyingTimeout time.Duration
	verifyURLAsHTTPS bool
}

func init() {
	rootCmd.AddCommand(testreceiverCmd)

	testreceiverCmd.Flags().StringVar(&testreceiverParams.serverPort, "server_port", "5000", "port to run local web server")
	testreceiverCmd.Flags().StringVar(&testreceiverParams.verifierAddress, "verifier_address", "localhost:4000", "address of verification server")
	testreceiverCmd.Flags().DurationVar(&testreceiverParams.verifyingTimeout, "verifying_timeout", 1000*time.Millisecond, "Specifies how long this client will wait for verification to finish before abandoning.")
	testreceiverCmd.Flags().BoolVar(&testreceiverParams.verifyURLAsHTTPS, "verify_as_https_url", false, "If true, assumes that URL uses https:// prefix; otherwise, assumes http://")
}

func startServer(testreceiverParams *testreceiverParameters) {

	// Establish the gRPC connection that the client will use to connect to the
	// signatory server.  This basic example uses unauthenticated connections
	// which should not be used in a production environment.
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(testreceiverParams.verifierAddress, opts...)
	if err != nil {
		logger.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Create a reusable Signatory Client that provides a lightweight wrapper
	// around the RPC client stub.  This code performs some basic request
	// timeout and error handling logic.
	clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: testreceiverParams.verifyingTimeout}
	signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

	// API routes
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		requestDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			logger.Errorf("Error dumping request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		requestBody, err := ioutil.ReadAll(req.Body)
		if err != nil {
			logger.Errorf("Error reading request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Normally an application server will have an indication of whether a
		// request was received using HTTPS or not, but this simple server
		// implementation doesn't make that assumption. If running this behind
		// an HTTPS endpoint, enable the --verify_as_https_url flag.
		var uriScheme string
		if testreceiverParams.verifyURLAsHTTPS {
			uriScheme = "https://"
		} else {
			uriScheme = "http://"
		}

		urlStringReconstruction := uriScheme + req.Host + req.URL.RequestURI()

		reqInfo := &api.RequestInfo{}
		signatory.SetRequestInfo(reqInfo, urlStringReconstruction, requestBody)
		signatory.SetRequestSignatures(reqInfo, req.Header["X-Ads-Cert-Auth"])

		verificationResponse, err := signatoryClient.VerifyAuthenticatedConnection(
			&api.AuthenticatedConnectionVerificationRequest{
				RequestInfo: []*api.RequestInfo{reqInfo},
			})
		if err != nil {
			logger.Warningf("unable to verify message: %v", err)
		}
		verificationResponseProtoText := prototext.Format(verificationResponse)

		verificationResponseText := fmt.Sprintf("Reconstructed URL:%s\nIncoming HTTP request (approximate):\n%s\n\nVerification result:\n%s",
			urlStringReconstruction, string(requestDump), verificationResponseProtoText)
		logger.Info(verificationResponseText)
		w.Write([]byte(verificationResponseText))
	})

	port := fmt.Sprintf(":%s", testreceiverParams.serverPort)

	fmt.Println("Server is running on port" + port)
	if err := http.ListenAndServe(port, nil); err != nil {
		logger.Errorf("Error starting HTTP server: %v", err)
	}
}
