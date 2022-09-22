package cmd

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
)

func BenchmarkSigningRequest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testsignParams := &testsignParameters{}
		testsignParams.url = "https://adscerttestverifier.dev"
		testsignParams.serverAddress = "localhost:3000"
		testsignParams.body = ""
		testsignParams.signingTimeout = 10 * time.Millisecond
		signRequest(testsignParams)
	}
}

func BenchmarkVerifyingRequest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testverifyParams := &testverifyParameters{}
		testverifyParams.destinationURL = "https://adscerttestverifier.dev"
		testverifyParams.serverAddress = "localhost:4000"
		testverifyParams.body = ""
		testverifyParams.verifyingTimeout = 10 * time.Millisecond
		testverifyParams.signatureMessage = "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=jsLwC53YySqG&status=1&timestamp=220816T221250&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=NfCC9zQeS3og&sigu=1tkmSdEe-5D7"
		verifyRequest(testverifyParams)
	}
}

func BenchmarkWebReceiver(b *testing.B) {
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("GET", "http://adscerttestverifier.dev:5000", nil)
		if err != nil {
			fmt.Println("Errored when creating request")
			b.Fail()
		}

		req.Header.Add("X-Ads-Cert-Auth", "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=Ppq82bU_LjD-&status=1&timestamp=220914T143647&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=uKm1qVmfrMeT&sigu=jkKZoB9TKzd_")
		client := &http.Client{}
		client.Do(req)
	}
}

func BenchmarkSignSendAndVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testURL := "http://adscerttestverifier.dev:5000"

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
			b.Fail()
		}
		signatureMessage := signatureResponse.GetRequestInfo().SignatureInfo[0].SignatureMessage

		// Send Request to Web Server
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			fmt.Println("Errored when creating request")
			b.Fail()
		}

		req.Header.Add("X-Ads-Cert-Auth", signatureMessage)

		client := &http.Client{}
		client.Do(req)
	}
}
