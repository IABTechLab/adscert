//go:build integration
// +build integration

package cmd

import (
	"testing"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
)

//
func TestSigningRequest(t *testing.T) {
	testsignParams := &testsignParameters{}
	testsignParams.url = "https://adscerttestverifier.dev"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 5 * time.Millisecond
	// fails on the first run since no records yet
	if signRequest(testsignParams).GetSignatureOperationStatus() != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_SIGNATORY_INTERNAL_ERROR {
		t.Fail()
	} else {
		time.Sleep(5 * time.Second)
		// succeeds on second run
		if signRequest(testsignParams).GetSignatureOperationStatus() != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK {
			t.Fail()
		}
	}
}

func TestVerificationRequest(t *testing.T) {
	testverifyParams := &testverifyParameters{}
	testverifyParams.destinationURL = "https://adscerttestverifier.dev"
	testverifyParams.serverAddress = "localhost:4000"
	testverifyParams.body = ""
	testverifyParams.verifyingTimeout = 20 * time.Millisecond
	testverifyParams.signatureMessage = "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=jsLwC53YySqG&status=1&timestamp=220816T221250&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=NfCC9zQeS3og&sigu=1tkmSdEe-5D7"
	if verifyRequest(testverifyParams).GetVerificationOperationStatus() != api.VerificationOperationStatus_VERIFICATION_OPERATION_STATUS_OK {
		t.Fail()
	}
}
