package cmd

import (
	// "net/http"
	"fmt"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
	"math"
	"testing"
	"time"
)

func TestLoadSigningRequest(t *testing.T) {
	testsignParams := &testsignParameters{}
	testsignParams.url = "https://adscerttestverifier.dev"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 1 * time.Second

	testsPerTestSize := 10
	c := make(chan api.SignatureOperationStatus)
	iterationResults := map[int][]float64{}
	for numOfRequests := 10; numOfRequests <= 10000; numOfRequests *= 10 {
		for i := 0; i < testsPerTestSize; i++ {
			iterationResult := sendSignatureRequests(numOfRequests, testsignParams, c)
			iterationResults[iterationResult[0]] = append(iterationResults[iterationResult[0]], float64(iterationResult[1]))
		}
	}

	for key, value := range iterationResults {
		fmt.Printf("%v Signing Attempts: %v succeeded\n", key, value)
	}
	plotResults(iterationResults)
}

func plotResults(iterationResults map[int][]float64) {
	group1 := plotter.Values{}
	// group2 := plotter.Values{}
	// group3 := plotter.Values{}
	// group4 := plotter.Values{}
	// group5 := plotter.Values{}
	// group6 := plotter.Values{}
	// group7 := plotter.Values{}
	// group8 := plotter.Values{}
	// group9 := plotter.Values{}
	// group10 := plotter.Values{}

	for i := 0; i <= 4; i++ {
		group1 = append(group1, iterationResults[int(math.Pow(10, float64(i+1)))][i])
		// group2 = append(group2, iterationResults[int(math.Pow(10, float64(i+1)))][i+1])
		// group3 = append(group3, iterationResults[int(math.Pow(10, float64(i+1)))][i+2])
		// group4 = append(group4, iterationResults[int(math.Pow(10, float64(i+1)))][i+3])
		// group5 = append(group5, iterationResults[int(math.Pow(10, float64(i+1)))][i+4])
		// group6 = append(group6, iterationResults[int(math.Pow(10, float64(i+1)))][i+5])
		// group7 = append(group7, iterationResults[int(math.Pow(10, float64(i+1)))][i+6])
		// group8 = append(group8, iterationResults[int(math.Pow(10, float64(i+1)))][i+7])
		// group9 = append(group9, iterationResults[int(math.Pow(10, float64(i+1)))][i+8])
		// group10 = append(group10, iterationResults[int(math.Pow(10, float64(i+1)))][i+9])
	}

	p := plot.New()

	p.Title.Text = "Bar chart"
	p.Y.Label.Text = "Heights"

	w := vg.Points(2)

	barsA, err := plotter.NewBarChart(group1, w)
	if err != nil {
		panic(err)
	}
	barsA.LineStyle.Width = vg.Length(0)
	barsA.Color = plotutil.Color(0)
	barsA.Offset = -w

	p.Add(barsA)
	p.Legend.Add("Group 1", barsA)

	// bars := []*plotter.BarChart{}
	// for _, group := range  {
	// 	aBar, err := plotter.NewBarChart(group, w)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	aBar.LineStyle.Width = vg.Length(0)
	// 	aBar.Color = plotutil.Color(0)
	// 	aBar.Offset = -w
	// 	bars = append(bars, aBar)

	// }
	// for i, bar := range bars {
	// 	p.Add(bar)
	// 	p.Legend.Add("iteration: "+fmt.Sprint(i), bar)
	// }
	p.Legend.Top = true
	p.NominalX("10", "100", "1000", "10000")

	if err := p.Save(10*vg.Inch, 6*vg.Inch, "barchart.png"); err != nil {
		panic(err)
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
