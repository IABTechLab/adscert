//go:build integration
// +build integration

package cmd

import (
	"testing"
	"time"
)

//
func TestSigningRequest(t *testing.T) {
	testsignParams := &testsignParameters{}
	testsignParams.url = "https://moatads.com"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 5 * time.Millisecond
	if signRequest(testsignParams) != nil {
		t.Fail()
	}
}

// func example(t *testing.T) {
// 	if a.func("user1", "pass1") == "" {
// 		t.Fail()
// 	}
// }
