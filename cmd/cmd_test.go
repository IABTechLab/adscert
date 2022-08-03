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
	testsignParams.url = "https://moatads.com"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 5 * time.Millisecond
	// fails on the first run since no records yet
	if signRequest(testsignParams).GetSignatureOperationStatus() != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_SIGNATORY_INTERNAL_ERROR {
		t.Fail()
	}
	// succeeds on second run
	if signRequest(testsignParams).GetSignatureOperationStatus() != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK {
		t.Fail()
	}
}

// func example(t *testing.T) {
// 	if a.func("user1", "pass1") == "" {
// 		t.Fail()
// 	}
// }
