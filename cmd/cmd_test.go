//go:build integration
// +build integration

package cmd

import (
	"fmt"
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
	// fails on the first run since no records yet
	if signRequest(testsignParams) != fmt.Errorf("no records for invoked url") {
		t.Fail()
	}
	// succeeds on the second run after records added
	if signRequest(testsignParams) != nil {
		t.Fail()
	}
}

// func example(t *testing.T) {
// 	if a.func("user1", "pass1") == "" {
// 		t.Fail()
// 	}
// }
