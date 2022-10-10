package cmd

import (
	// "net/http"
	"fmt"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"testing"
	"time"
)

func TestLoad10To1000SigningRequest(t *testing.T) {
	testsignParams := &testsignParameters{}
	testsignParams.url = "https://adscerttestverifier.dev"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 10 * time.Millisecond

	c := make(chan api.SignatureOperationStatus)
	iterationResults := map[int]int{}
	for numOfRequests := 10; numOfRequests <= 1000; numOfRequests *= 10 {
		iterationResult := sendSignatureRequests(numOfRequests, testsignParams, c)
		iterationResults[iterationResult[0]] = iterationResult[1]
	}

	for key, value := range iterationResults {
		fmt.Printf("%v Signing Attempts: %v succeeded\n", key, value)
	}
}

func sendSignatureRequests(numOfRequests int, testsignParams *testsignParameters, c chan api.SignatureOperationStatus) []int {
	for i := 0; i < numOfRequests; i++ {
		go signToChannel(testsignParams, c)
	}

	var res []api.SignatureOperationStatus
	successfulSignatureAttempts := 0
	for i := 0; i < numOfRequests; i++ {
		operationStatus := <-c
		if operationStatus == api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK {
			successfulSignatureAttempts += 1
		}
		res = append(res, operationStatus)
	}

	iterationResult := []int{len(res), successfulSignatureAttempts}
	return iterationResult
}

func signToChannel(testsignParams *testsignParameters, c chan api.SignatureOperationStatus) {
	signatureStatus := signRequest(testsignParams)
	c <- signatureStatus.GetSignatureOperationStatus() // send status to c
}

// func LoadTestWebReceiver(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		req, err := http.NewRequest("GET", "http://adscerttestverifier.dev:5000", nil)
// 		if err != nil {
// 			fmt.Println("Errored when creating request")
// 			b.Fail()
// 		}

// 		req.Header.Add("X-Ads-Cert-Auth", "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=Ppq82bU_LjD-&status=1&timestamp=220914T143647&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=uKm1qVmfrMeT&sigu=jkKZoB9TKzd_")
// 		client := &http.Client{}
// 		client.Do(req)
// 	}
// }

// func LoadTestSignSendAndVerify(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		testURL := "http://adscerttestverifier.dev:5000"

// 		// Sign Request
// 		retries := 10
// 		testsignParams := &testsignParameters{}
// 		testsignParams.url = testURL
// 		testsignParams.serverAddress = "localhost:3000"
// 		testsignParams.body = ""
// 		testsignParams.signingTimeout = 10 * time.Millisecond
// 		signatureResponse := signRequest(testsignParams)
// 		for signatureResponse.GetSignatureOperationStatus() != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK && retries > 0 {
// 			time.Sleep(5 * time.Second)
// 			signatureResponse = signRequest(testsignParams)
// 		}
// 		if retries == 0 {
// 			b.Fail()
// 		}
// 		signatureMessage := signatureResponse.GetRequestInfo().SignatureInfo[0].SignatureMessage

// 		// Send Request to Web Server
// 		req, err := http.NewRequest("GET", testURL, nil)
// 		if err != nil {
// 			fmt.Println("Errored when creating request")
// 			b.Fail()
// 		}

// 		req.Header.Add("X-Ads-Cert-Auth", signatureMessage)

// 		client := &http.Client{}
// 		client.Do(req)
// 	}
// }
