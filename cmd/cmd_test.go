package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
)

func TestSigningRequest(t *testing.T) {
	testsignParams := &testsignParameters{}
	testsignParams.url = "https://adscerttestverifier.dev"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 10 * time.Millisecond
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
	testverifyParams.verifyingTimeout = 10 * time.Millisecond
	testverifyParams.signatureMessage = "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=jsLwC53YySqG&status=1&timestamp=220816T221250&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=NfCC9zQeS3og&sigu=1tkmSdEe-5D7"
	if verifyRequest(testverifyParams).GetVerificationInfo()[0].GetSignatureDecodeStatus()[0] != api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_COUNTERPARTY_LOOKUP_ERROR {
		t.Fail()
	} else {
		time.Sleep(5 * time.Second)
		// succeeds on second run
		if verifyRequest(testverifyParams).GetVerificationInfo()[0].GetSignatureDecodeStatus()[0] != api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID {
			t.Fail()
		}
	}
}

func TestWebReciever(t *testing.T) {
	urlValue := "https://adscerttestverifier.dev"
	urlData, err := json.Marshal(urlValue)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:5000", bytes.NewBuffer(urlData))
	if err != nil {
		t.Fail()
	}

	req.Header.Set("X-Ads-Cert-Auth", "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=mBJo7EYj9XF9&status=1&timestamp=220810T142237&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=ugN9tqMd6h0p&sigu=pxQd8BV20lHg")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Errored when sending request to the server")
		t.Fail()
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fail()
	}

	fmt.Println(resp.Status)
	fmt.Println(string(responseBody))

}
