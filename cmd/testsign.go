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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
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
			signatureResponse := signRequest(testsignParams)

			if testsignParams.sendRequest {
				req, err := http.NewRequest(testsignParams.method, testsignParams.url, bytes.NewReader([]byte(testsignParams.body)))
				if err != nil {
					logger.Fatalf("Failed to construct HTTP request: %v", err)
				}

				for _, signature := range signatureResponse.GetRequestInfo().GetSignatureInfo() {
					req.Header.Add("X-Ads-Cert-Auth", signature.GetSignatureMessage())
				}

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					logger.Fatalf("Failed to invoke HTTP request: %v", err)
				}
				fmt.Printf("client: status code: %d\n", resp.StatusCode)
				respBody, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					logger.Fatalf("Failed to read response: %v", err)
				}
				fmt.Print(string(respBody))
			}
		},
	}
)

type testsignParameters struct {
	url            string
	serverAddress  string
	body           string
	signingTimeout time.Duration
	sendRequest    bool
	method         string
	signURLAsHTTPS bool
}

func init() {
	rootCmd.AddCommand(testsignCmd)

	testsignCmd.Flags().StringVar(&testsignParams.url, "url", "", "URL to invoke")
	testsignCmd.Flags().BoolVar(&testsignParams.signURLAsHTTPS, "sign_as_https_url", false, "If true, rewrites an http:// URL to include an https:// prefix")
	testsignCmd.Flags().StringVar(&testsignParams.serverAddress, "server_address", "localhost:3000", "address of grpc server")
	testsignCmd.Flags().StringVar(&testsignParams.body, "body", "", "POST request body")
	testsignCmd.Flags().DurationVar(&testsignParams.signingTimeout, "signing_timeout", 50*time.Millisecond, "Specifies how long this client will wait for signing to finish before abandoning.")
	testsignCmd.Flags().BoolVar(&testsignParams.sendRequest, "send_request", false, "If true, invokes the specified URL on the remote server")
	testsignCmd.Flags().StringVar(&testsignParams.method, "method", "GET", "The HTTP request method, GET or POST")
}

func signRequest(testsignParams *testsignParameters) *api.AuthenticatedConnectionSignatureResponse {

	// Establish the gRPC connection that the client will use to connect to the
	// signatory server.  This basic example uses unauthenticated connections
	// which should not be used in a production environment.
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(testsignParams.serverAddress, opts...)
	if err != nil {
		logger.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Create a reusable Signatory Client that provides a lightweight wrapper
	// around the RPC client stub.  This code performs some basic request
	// timeout and error handling logic.
	clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: testsignParams.signingTimeout}
	signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

	// Rewrite an HTTP url as HTTPS if requested by command line flag.
	var urlToSign string
	if strings.HasPrefix(testsignParams.url, "http://") && testsignParams.signURLAsHTTPS {
		urlToSign = "https://" + testsignParams.url[7:]
	} else {
		urlToSign = testsignParams.url
	}

	// The RequestInfo proto contains details about the individual ad request
	// being signed.  A SetRequestInfo helper function derives a hash of the
	// destination URL and body, setting these value on the RequestInfo message.
	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, urlToSign, []byte(testsignParams.body))

	// Request the signature.
	logger.Infof("signing request for URL: %v", urlToSign)
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
	} else {
		logger.Warningf("signature response is missing")
	}
	return signatureResponse
}
