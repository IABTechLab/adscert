package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"encoding/hex"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

func TestLoadNoOp(t *testing.T) {
	timeoutList := []time.Duration{1 * time.Millisecond}
	for _, timeout := range timeoutList {
		signBatchesAndPlot(timeout, true)
	}

}

func TestLoadSigning(t *testing.T) {
	timeoutList := []time.Duration{1 * time.Millisecond}
	for _, timeout := range timeoutList {
		signBatchesAndPlot(timeout, false)
	}

}

func DeactivatedTestLoadVerification(t *testing.T) {
	timeoutList := []time.Duration{10 * time.Millisecond, 100 * time.Millisecond, 1000 * time.Millisecond}
	for _, timeout := range timeoutList {
		verifyBatchesAndPlot(timeout)
	}

}

func DeactivatedTestLoadWebReceiver(t *testing.T) {
	timeoutList := []time.Duration{10 * time.Millisecond, 100 * time.Millisecond, 1000 * time.Millisecond}
	for _, timeout := range timeoutList {
		webReceiverBatchesAndPlot(timeout)
	}

}

func DeactivatedTestLoadEndToEnd(t *testing.T) {
	timeoutList := []time.Duration{10 * time.Millisecond, 100 * time.Millisecond, 1000 * time.Millisecond}
	for _, timeout := range timeoutList {
		e2eBatchesAndPlot(timeout)
	}

}

func signBatchesAndPlot(timeout time.Duration, isNoOp bool) {
	testsignParams := &testsignParameters{}
	if isNoOp {
		testsignParams.url = "dryrun"
	} else {
		testsignParams.url = "https://adscerttestverifier.dev"
	}
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = timeout

	testsPerTestSize := 10
	c := make(chan api.SignatureOperationStatus)

	// Establish the gRPC connection that the client will use to connect to the
	// signatory server.  This basic example uses unauthenticated connections
	// which should not be used in a production environment.
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(testsignParams.serverAddress, opts...)
	if err != nil {
		logger.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	iterationResults := map[int][]float64{}
	lowestSuccessPercent := 1.00
	numOfRequests := 1
	for lowestSuccessPercent > 0.50 {
		numOfRequests *= 2
		retries := 1
		if numOfRequests == 2 {
			retries = 20
		}
		for retries > 0 {
			iterationResults[numOfRequests] = []float64{}
			lowestSuccessPercent = 1.00
			for i := 0; i < testsPerTestSize; i++ {
				iterationResult := sendSignatureRequestsOverConnection(numOfRequests, testsignParams, c, conn)
				iterationResultSuccessPercent := float64(iterationResult[1]) / float64(numOfRequests)
				if lowestSuccessPercent > iterationResultSuccessPercent {
					lowestSuccessPercent = iterationResultSuccessPercent
				}
				iterationResults[numOfRequests] = append(iterationResults[numOfRequests], float64(iterationResult[1]))
			}
			if lowestSuccessPercent < 0.50 {
				retries--
			} else {
				retries = 0
			}
		}
	}

	for key, iterationResult := range iterationResults {
		fmt.Printf("%v Signing Attempts: %v succeeded\n", key, iterationResult)
	}
	if isNoOp {
		plotResults(iterationResults, numOfRequests, timeout, "noop")
	} else {
		plotResults(iterationResults, numOfRequests, timeout, "sign")
	}

}

func sendSignatureRequestsOverConnection(numOfRequests int, testsignParams *testsignParameters, c chan api.SignatureOperationStatus, conn *grpc.ClientConn) []int {
	for i := 0; i < numOfRequests; i++ {
		go signToChannelOverConnection(testsignParams, c, conn)
	}

	var res []api.SignatureOperationStatus
	successfulSignatureAttempts := 0
	for i := 0; i < numOfRequests; i++ {
		operationStatus := <-c
		if operationStatus == api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK {
			successfulSignatureAttempts++
		}
		res = append(res, operationStatus)
	}

	iterationResult := []int{len(res), successfulSignatureAttempts}
	return iterationResult
}

func signToChannelOverConnection(testsignParams *testsignParameters, c chan api.SignatureOperationStatus, conn *grpc.ClientConn) {
	signatureStatus := signRequestOverConnection(testsignParams, conn)
	c <- signatureStatus.GetSignatureOperationStatus() // send status to c
}

func verifyBatchesAndPlot(timeout time.Duration) {
	testverifyParams := &testverifyParameters{}
	testverifyParams.destinationURL = "https://adscerttestverifier.dev"
	testverifyParams.serverAddress = "localhost:4000"
	testverifyParams.body = ""
	testverifyParams.verifyingTimeout = timeout
	testverifyParams.signatureMessage = "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=jsLwC53YySqG&status=1&timestamp=220816T221250&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=NfCC9zQeS3og&sigu=1tkmSdEe-5D7"

	testsPerTestSize := 10
	c := make(chan api.SignatureDecodeStatus)
	iterationResults := map[int][]float64{}
	lowestSuccessPercent := 1.00
	numOfRequests := 1
	for lowestSuccessPercent > 0.50 {
		numOfRequests *= 2
		retries := 1
		if numOfRequests == 2 {
			retries = 20
		}
		for retries > 0 {
			iterationResults[numOfRequests] = []float64{}
			lowestSuccessPercent = 1.00
			for i := 0; i < testsPerTestSize; i++ {
				iterationResult := sendVerificationRequests(numOfRequests, testverifyParams, c)
				iterationResultSuccessPercent := float64(iterationResult[1]) / float64(numOfRequests)
				if lowestSuccessPercent > iterationResultSuccessPercent {
					lowestSuccessPercent = iterationResultSuccessPercent
				}
				iterationResults[numOfRequests] = append(iterationResults[numOfRequests], float64(iterationResult[1]))
			}
			if lowestSuccessPercent < 0.50 {
				retries--
			} else {
				retries = 0
			}
		}
	}

	for key, iterationResult := range iterationResults {
		fmt.Printf("%v Verification Attempts: %v succeeded\n", key, iterationResult)
	}
	plotResults(iterationResults, numOfRequests, timeout, "verify")

}

func sendVerificationRequests(numOfRequests int, testverifyParams *testverifyParameters, c chan api.SignatureDecodeStatus) []int {
	for i := 0; i < numOfRequests; i++ {
		go verifyToChannel(testverifyParams, c)
	}

	var res []api.SignatureDecodeStatus
	successfulVerificationAttempts := 0
	for i := 0; i < numOfRequests; i++ {
		operationStatus := <-c
		if operationStatus == api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID {
			successfulVerificationAttempts++
		}
		res = append(res, operationStatus)
	}

	iterationResult := []int{len(res), successfulVerificationAttempts}
	return iterationResult
}

func verifyToChannel(testverifyParams *testverifyParameters, c chan api.SignatureDecodeStatus) {
	verificationResponse := verifyRequest(testverifyParams)
	if len(verificationResponse.GetVerificationInfo()) > 0 && len(verificationResponse.GetVerificationInfo()[0].GetSignatureDecodeStatus()) > 0 {
		signatureStatus := verificationResponse.GetVerificationInfo()[0].GetSignatureDecodeStatus()[0]
		c <- signatureStatus // send status to c
	} else {
		c <- api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_UNDEFINED
	}
}

func webReceiverBatchesAndPlot(timeout time.Duration) {
	testsPerTestSize := 10
	c := make(chan string)
	iterationResults := map[int][]float64{}
	lowestSuccessPercent := 1.00
	numOfRequests := 1
	for lowestSuccessPercent > 0.50 {
		numOfRequests *= 2
		retries := 1
		if numOfRequests == 2 {
			retries = 20
		}
		for retries > 0 {
			iterationResults[numOfRequests] = []float64{}
			lowestSuccessPercent = 1.00
			for i := 0; i < testsPerTestSize; i++ {
				iterationResult := sendWebRequests(numOfRequests, timeout, c)
				iterationResultSuccessPercent := float64(iterationResult[1]) / float64(numOfRequests)
				if lowestSuccessPercent > iterationResultSuccessPercent {
					lowestSuccessPercent = iterationResultSuccessPercent
				}
				iterationResults[numOfRequests] = append(iterationResults[numOfRequests], float64(iterationResult[1]))
			}
			if lowestSuccessPercent < 0.50 {
				retries--
			} else {
				retries = 0
			}
		}
	}

	for key, iterationResult := range iterationResults {
		fmt.Printf("%v Web Server Verification Attempts: %v succeeded\n", key, iterationResult)
	}

	plotResults(iterationResults, numOfRequests, timeout, "web")

}

func sendWebRequests(numOfRequests int, timeout time.Duration, c chan string) []int {
	for i := 0; i < numOfRequests; i++ {
		go webResponseToChannel(timeout, c)
	}

	var res []string
	successfulWebAttempts := 0
	for i := 0; i < numOfRequests; i++ {
		operationStatus := <-c
		fmt.Println(operationStatus)
		if strings.Contains(operationStatus, "SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID") {
			successfulWebAttempts++
		}
		res = append(res, operationStatus)
	}

	iterationResult := []int{len(res), successfulWebAttempts}
	return iterationResult
}

func webResponseToChannel(timeout time.Duration, c chan string) {
	req, err := http.NewRequest("GET", "http://adscerttestverifier.dev:5000", nil)
	if err != nil {
		responseBodyString := "Errored when creating request"
		fmt.Println(responseBodyString)
		c <- responseBodyString
		return
	}

	req.Header.Add("X-Ads-Cert-Auth", "from=adscerttestsigner.dev&from_key=LxqTmA&invoking=adscerttestverifier.dev&nonce=Ppq82bU_LjD-&status=1&timestamp=220914T143647&to=adscerttestverifier.dev&to_key=uNzTFA; sigb=uKm1qVmfrMeT&sigu=jkKZoB9TKzd_")
	client := &http.Client{
		Timeout: timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		responseBodyString := "Errored when sending request to the server"
		fmt.Println(responseBodyString)
		c <- responseBodyString
		return
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		responseBodyString := "Error on body read"
		fmt.Println(responseBodyString)
		c <- responseBodyString
		return
	}

	responseBodyString := string(responseBody)
	c <- responseBodyString // send status to c

}

func e2eBatchesAndPlot(timeout time.Duration) {
	testsPerTestSize := 10
	c := make(chan string)
	iterationResults := map[int][]float64{}
	lowestSuccessPercent := 1.00
	numOfRequests := 1
	for lowestSuccessPercent > 0.50 {
		numOfRequests *= 2
		retries := 1
		if numOfRequests == 2 {
			retries = 20
		}
		for retries > 0 {
			iterationResults[numOfRequests] = []float64{}
			lowestSuccessPercent = 1.00
			for i := 0; i < testsPerTestSize; i++ {
				iterationResult := sendEndToEndRequests(numOfRequests, timeout, c)
				iterationResultSuccessPercent := float64(iterationResult[1]) / float64(numOfRequests)
				if lowestSuccessPercent > iterationResultSuccessPercent {
					lowestSuccessPercent = iterationResultSuccessPercent
				}
				iterationResults[numOfRequests] = append(iterationResults[numOfRequests], float64(iterationResult[1]))
			}
			if lowestSuccessPercent < 0.50 {
				retries--
			} else {
				retries = 0
			}
		}
	}

	for key, iterationResult := range iterationResults {
		fmt.Printf("%v End-to-End Attempts: %v succeeded\n", key, iterationResult)
	}

	plotResults(iterationResults, numOfRequests, timeout, "e2e")

}

func sendEndToEndRequests(numOfRequests int, timeout time.Duration, c chan string) []int {
	for i := 0; i < numOfRequests; i++ {
		go e2eToChannelWithTimeout(timeout, c)
	}

	var res []string
	successfulE2eAttempts := 0
	for i := 0; i < numOfRequests; i++ {
		operationStatus := <-c
		fmt.Println(operationStatus)
		if strings.Contains(operationStatus, "SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID") {
			successfulE2eAttempts++
		}
		res = append(res, operationStatus)
	}

	iterationResult := []int{len(res), successfulE2eAttempts}
	return iterationResult
}

func e2eToChannelWithTimeout(timeout time.Duration, c chan string) {
	c2 := make(chan string)
	go e2eToChannel(timeout, c2)
	select {
	case <-time.After(timeout):
		c <- "end to end test timed out"
	case operationStatus := <-c2:
		c <- operationStatus
	}
}

func e2eToChannel(timeout time.Duration, c chan string) {
	testURL := "http://adscerttestverifier.dev:5000"

	testsignParams := &testsignParameters{}
	testsignParams.url = testURL
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = timeout
	signatureResponse := signRequest(testsignParams)
	if signatureResponse.GetSignatureOperationStatus() != api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK {
		responseBodyString := "Signing request failed"
		fmt.Println(responseBodyString)
		c <- responseBodyString
		return
	}
	signatureMessage := signatureResponse.GetRequestInfo().SignatureInfo[0].SignatureMessage

	// Send Request to Web Server
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		responseBodyString := "Errored when creating request"
		fmt.Println(responseBodyString)
		c <- responseBodyString
		return
	}

	req.Header.Add("X-Ads-Cert-Auth", signatureMessage)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		responseBodyString := "Errored when sending request to the server"
		fmt.Println(responseBodyString)
		c <- responseBodyString
		return
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		responseBodyString := "Error on response body read"
		fmt.Println(responseBodyString)
		c <- responseBodyString
		return
	}

	responseBodyString := string(responseBody)
	c <- responseBodyString // send status to c

}

func plotResults(iterationResults map[int][]float64, maxNumOfRequests int, timeout time.Duration, opType string) {
	group1 := plotter.Values{}
	group2 := plotter.Values{}
	group3 := plotter.Values{}
	group4 := plotter.Values{}
	group5 := plotter.Values{}
	group6 := plotter.Values{}
	group7 := plotter.Values{}
	group8 := plotter.Values{}
	group9 := plotter.Values{}
	group10 := plotter.Values{}

	for i := 2; i <= maxNumOfRequests; i *= 2 {
		group1 = append(group1, (iterationResults[i][0]/float64(i))*100)
		group2 = append(group2, (iterationResults[i][1]/float64(i))*100)
		group3 = append(group3, (iterationResults[i][2]/float64(i))*100)
		group4 = append(group4, (iterationResults[i][3]/float64(i))*100)
		group5 = append(group5, (iterationResults[i][4]/float64(i))*100)
		group6 = append(group6, (iterationResults[i][5]/float64(i))*100)
		group7 = append(group7, (iterationResults[i][6]/float64(i))*100)
		group8 = append(group8, (iterationResults[i][7]/float64(i))*100)
		group9 = append(group9, (iterationResults[i][8]/float64(i))*100)
		group10 = append(group10, (iterationResults[i][9]/float64(i))*100)
	}

	p := plot.New()
	switch {
	case opType == "noop":
		p.Title.Text = fmt.Sprintf("NOOP: Percent of messages successfully returned per batch of size 2^X concurrent requests. 10 runs per batch size. Timeout: %s", fmt.Sprint(timeout))
		p.Y.Label.Text = "Percent Successful No Operation Attemps"
	case opType == "sign":
		p.Title.Text = fmt.Sprintf("SIGNING: Percent of successful signed requests per batch of size 2^X concurrent requests. 10 runs per batch size. Timeout: %s", fmt.Sprint(timeout))
		p.Y.Label.Text = "Percent Successful Signing Attemps"
	case opType == "verify":
		p.Title.Text = fmt.Sprintf("VERIFYING: Percent of successful verified requests per batch of size 2^X concurrent requests. 10 runs per batch size. Timeout: %s", fmt.Sprint(timeout))
		p.Y.Label.Text = "Percent Successful Verification Attemps"
	case opType == "web":
		p.Title.Text = fmt.Sprintf("WEB RECEIVER: Percent of successful verified requests per batch of size 2^X concurrent requests. 10 runs per batch size. Timeout: %s", fmt.Sprint(timeout))
		p.Y.Label.Text = "Percent Successful Web Verification Attemps"
	case opType == "e2e":
		p.Title.Text = fmt.Sprintf("End To End: Percent of successful signed, sent, and verified requests per batch of size 2^X concurrent requests. 10 runs per batch size. Timeout: %s", fmt.Sprint(timeout))
		p.Y.Label.Text = "Percent Successful End to End Attemps"
	}

	w := vg.Points(4)

	bars1, err := plotter.NewBarChart(group1, w)
	if err != nil {
		panic(err)
	}
	bars1.LineStyle.Width = vg.Length(0)
	bars1.Color = plotutil.Color(0)
	bars1.Offset = -4.5 * w

	bars2, err := plotter.NewBarChart(group2, w)
	if err != nil {
		panic(err)
	}
	bars2.LineStyle.Width = vg.Length(0)
	bars2.Color = plotutil.Color(1)
	bars2.Offset = -3.5 * w

	bars3, err := plotter.NewBarChart(group3, w)
	if err != nil {
		panic(err)
	}
	bars3.LineStyle.Width = vg.Length(0)
	bars3.Color = plotutil.Color(2)
	bars3.Offset = -2.5 * w

	bars4, err := plotter.NewBarChart(group4, w)
	if err != nil {
		panic(err)
	}
	bars4.LineStyle.Width = vg.Length(0)
	bars4.Color = plotutil.Color(3)
	bars4.Offset = -1.5 * w

	bars5, err := plotter.NewBarChart(group5, w)
	if err != nil {
		panic(err)
	}
	bars5.LineStyle.Width = vg.Length(0)
	bars5.Color = plotutil.Color(4)
	bars5.Offset = -0.5 * w

	bars6, err := plotter.NewBarChart(group6, w)
	if err != nil {
		panic(err)
	}
	bars6.LineStyle.Width = vg.Length(0)
	bars6.Color = plotutil.Color(5)
	bars6.Offset = 0.5 * w

	bars7, err := plotter.NewBarChart(group7, w)
	if err != nil {
		panic(err)
	}
	bars7.LineStyle.Width = vg.Length(0)
	bars7.Color = plotutil.Color(6)
	bars7.Offset = 1.5 * w

	bars8, err := plotter.NewBarChart(group8, w)
	if err != nil {
		panic(err)
	}
	bars8.LineStyle.Width = vg.Length(0)
	bars8.Color = plotutil.Color(7)
	bars8.Offset = 2.5 * w

	bars9, err := plotter.NewBarChart(group9, w)
	if err != nil {
		panic(err)
	}
	bars9.LineStyle.Width = vg.Length(0)
	bars9.Color = plotutil.Color(8)
	bars9.Offset = 3.5 * w

	bars10, err := plotter.NewBarChart(group10, w)
	if err != nil {
		panic(err)
	}
	bars10.LineStyle.Width = vg.Length(0)
	bars10.Color = plotutil.Color(9)
	bars10.Offset = 4.5 * w

	p.Add(bars1, bars2, bars3, bars4, bars5, bars6, bars7, bars8, bars9, bars10)
	p.Legend.Add("1st run", bars1)
	p.Legend.Add("2nd run", bars2)
	p.Legend.Add("3rd run", bars3)
	p.Legend.Add("4th run", bars4)
	p.Legend.Add("5th run", bars5)
	p.Legend.Add("6th run", bars6)
	p.Legend.Add("7th run", bars7)
	p.Legend.Add("8th run", bars8)
	p.Legend.Add("9th run", bars9)
	p.Legend.Add("10th run", bars10)

	p.Legend.Top = true

	if err := p.Save(10*vg.Inch, 6*vg.Inch, fmt.Sprintf("load_test_results/%sLoadTest%s.png", opType, fmt.Sprint(timeout))); err != nil {
		panic(err)
	}
}

func signRequestOverConnection(testsignParams *testsignParameters, conn *grpc.ClientConn) *api.AuthenticatedConnectionSignatureResponse {
	logger.Infof("Connecting to signatory server at %s\n", testsignParams.serverAddress)

	// Create a reusable Signatory Client that provides a lightweight wrapper
	// around the RPC client stub.  This code performs some basic request
	// timeout and error handling logic.
	clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: testsignParams.signingTimeout}
	signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

	// Rewrite an HTTP url as HTTPS if requested by command line flag.
	var urlToSign string
	if strings.HasPrefix(testsignParams.url, "http://") && testsignParams.signURLAsHTTPS {
		urlToSign = "https://" + testsignParams.url[7:]
		logger.Infof("Rewrote URL to HTTPS (from %s to %s)", testsignParams.url, urlToSign)
	} else {
		urlToSign = testsignParams.url
	}

	// The RequestInfo proto contains details about the individual ad request
	// being signed.  A SetRequestInfo helper function derives a hash of the
	// destination URL and body, setting these value on the RequestInfo message.
	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, urlToSign, []byte(testsignParams.body))

	logger.Infof("Calculated hashes:\n\t URL: %s\n\tBody: %s", hex.EncodeToString(reqInfo.UrlHash), hex.EncodeToString(reqInfo.BodyHash))

	// Request the signature.
	logger.Infof("Signing request for URL: %v", urlToSign)
	signatureResponse, err := signatoryClient.SignAuthenticatedConnection(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
		})
	if err != nil {
		logger.Warningf("unable to sign message: %v", err)
	}

	// In most circumstances a signatureResponse will be returned which includes
	// detals about the successful or failed signature attempt.
	if signatureResponse != nil {
		logger.Infof("signature response:\n%s", prototext.Format(signatureResponse))
	} else {
		logger.Warningf("signature response is missing")
	}
	return signatureResponse
}
