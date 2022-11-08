//go:build integration
// +build integration

package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
)

func TestSigningRequest(t *testing.T) {
	retries := 10
	testsignParams := &testsignParameters{}
	testsignParams.url = "http://adscerttestverifier.dev/"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 10 * time.Millisecond
	signatureStatus := signRequest(testsignParams).GetSignatureOperationStatus()
	for signatureStatus != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK && retries > 0 {
		time.Sleep(5 * time.Second)
		signatureStatus = signRequest(testsignParams).GetSignatureOperationStatus()
	}
	if retries == 0 {
		t.Fail()
	}

}

func TestVerificationRequest(t *testing.T) {
	retries := 10
	testverifyParams := &testverifyParameters{}
	testverifyParams.destinationURL = "https://adscerttestverifier.dev"
	testverifyParams.serverAddress = "localhost:4000"
	testverifyParams.body = ""
	testverifyParams.verifyingTimeout = 10 * time.Millisecond
	testverifyParams.signatureMessage = "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=jsLwC53YySqG&status=1&timestamp=220816T221250&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=NfCC9zQeS3og&sigu=1tkmSdEe-5D7"
	signatureStatus := verifyRequest(testverifyParams).GetVerificationInfo()[0].GetSignatureDecodeStatus()[0]
	for signatureStatus != api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID && retries > 0 {
		time.Sleep(5 * time.Second)
		signatureStatus = verifyRequest(testverifyParams).GetVerificationInfo()[0].GetSignatureDecodeStatus()[0]
		retries -= 1
	}
	if retries == 0 {
		t.Fail()
	}

}

func TestWebReceiver(t *testing.T) {
	req, err := http.NewRequest("GET", "http://adscerttestverifier.dev:5000/", nil)
	if err != nil {
		fmt.Println("Errored when creating request")
		t.Fail()
	}

	req.Header.Add("X-Ads-Cert-Auth", "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=2dkjnuc7Ys6C&status=1&timestamp=221108T210236&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=5usOiMogaDBt&sigu=KYG3Xyj4akUe")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Errored when sending request to the server")
		t.Fail()
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Unexpected error on body read: %v", err)
	}

	responseBodyString := string(responseBody)
	fmt.Println(resp.Status)
	fmt.Println(responseBodyString)

	if !strings.Contains(responseBodyString, "SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID") {
		t.Fatalf("responseBodyString incorrect: got %s, want SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID", responseBodyString)
	}
}

// End to End integration test
func TestSignSendAndVerify(t *testing.T) {
	testURL := "http://adscerttestverifier.dev:5000/"

	// Sign Request
	retries := 10
	testsignParams := &testsignParameters{}
	testsignParams.url = testURL
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 10 * time.Millisecond
	signatureResponse := signRequest(testsignParams)
	for signatureResponse.GetSignatureOperationStatus() != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK && retries > 0 {
		time.Sleep(5 * time.Second)
		signatureResponse = signRequest(testsignParams)
	}
	if retries == 0 {
		t.Fail()
	}
	signatureMessage := signatureResponse.GetRequestInfo().SignatureInfo[0].SignatureMessage

	// Send Request to Web Server
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		fmt.Println("Errored when creating request")
		t.Fail()
	}

	req.Header.Add("X-Ads-Cert-Auth", signatureMessage)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Errored when sending request to the server")
		t.Fail()
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Errored on body read")
		t.Fail()
	}

	// Print verification response
	responseBodyString := string(responseBody)
	fmt.Println(resp.Status)
	fmt.Println(responseBodyString)

	if !strings.Contains(responseBodyString, "SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID") {
		fmt.Println("Failed, signature invalid")
		t.Fail()
	}
}
