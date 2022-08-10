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
