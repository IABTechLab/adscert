package cmd

import (
	"testing"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

func BenchmarkSigningRequest(b *testing.B) {
	testsignParams = &testsignParameters{}

	testsignParams.url = "https://adscerttestverifier.dev"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 10 * time.Millisecond

	for i := 0; i < b.N; i++ {
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
		} else {
			logger.Warningf("signature response is missing")
		}
	}
}
