package cmd

import (
	"strings"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc"
)

func signRequestOverConnection(testsignParams *testsignParameters, conn *grpc.ClientConn) *api.AuthenticatedConnectionSignatureResponse {
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
	signatureResponse, _ := signatoryClient.SignAuthenticatedConnection(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
		})

	return signatureResponse
}

func verifyRequestOverConnection(testverifyParams *testverifyParameters, conn *grpc.ClientConn) *api.AuthenticatedConnectionVerificationResponse {
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
	verificationResponse, _ := signatoryClient.VerifyAuthenticatedConnection(
		&api.AuthenticatedConnectionVerificationRequest{
			RequestInfo: []*api.RequestInfo{reqInfo},
		})
	return verificationResponse
}
