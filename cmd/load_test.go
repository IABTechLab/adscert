package cmd

import (
	// "net/http"
	"fmt"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
	"testing"
	"time"
)

func TestLoadSigningRequest(t *testing.T) {
	testsignParams := &testsignParameters{}
	testsignParams.url = "https://adscerttestverifier.dev"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 20 * time.Millisecond

	testsPerTestSize := 10
	c := make(chan api.SignatureOperationStatus)
	iterationResults := map[int][]float64{}
	for numOfRequests := 10; numOfRequests <= 10000; numOfRequests *= 10 {
		for i := 0; i < testsPerTestSize; i++ {
			iterationResult := sendSignatureRequests(numOfRequests, testsignParams, c)
			iterationResults[iterationResult[0]] = append(iterationResults[iterationResult[0]], float64(iterationResult[1]))
		}
	}

	for key, iterationResult := range iterationResults {
		fmt.Printf("%v Signing Attempts: %v succeeded\n", key, iterationResult)
	}
	plotResults(iterationResults)
}

func plotResults(iterationResults map[int][]float64) {
	backdrop1 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop2 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop3 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop4 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop5 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop6 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop7 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop8 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop9 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	backdrop10 := plotter.Values{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}

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

	for i := 10; i <= 10000; i *= 10 {
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

	p.Title.Text = "Bar chart"
	p.Y.Label.Text = "Heights"

	w := vg.Points(10)

	bars1, err := plotter.NewBarChart(group1, w)
	if err != nil {
		panic(err)
	}
	bars1.LineStyle.Width = vg.Length(0)
	bars1.Color = plotutil.Color(1)
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
	bars3.Color = plotutil.Color(1)
	bars3.Offset = -2.5 * w

	bars4, err := plotter.NewBarChart(group4, w)
	if err != nil {
		panic(err)
	}
	bars4.LineStyle.Width = vg.Length(0)
	bars4.Color = plotutil.Color(1)
	bars4.Offset = -1.5 * w

	bars5, err := plotter.NewBarChart(group5, w)
	if err != nil {
		panic(err)
	}
	bars5.LineStyle.Width = vg.Length(0)
	bars5.Color = plotutil.Color(1)
	bars5.Offset = -0.5 * w

	bars6, err := plotter.NewBarChart(group6, w)
	if err != nil {
		panic(err)
	}
	bars6.LineStyle.Width = vg.Length(0)
	bars6.Color = plotutil.Color(1)
	bars6.Offset = 0.5 * w

	bars7, err := plotter.NewBarChart(group7, w)
	if err != nil {
		panic(err)
	}
	bars7.LineStyle.Width = vg.Length(0)
	bars7.Color = plotutil.Color(1)
	bars7.Offset = 1.5 * w

	bars8, err := plotter.NewBarChart(group8, w)
	if err != nil {
		panic(err)
	}
	bars8.LineStyle.Width = vg.Length(0)
	bars8.Color = plotutil.Color(1)
	bars8.Offset = 2.5 * w

	bars9, err := plotter.NewBarChart(group9, w)
	if err != nil {
		panic(err)
	}
	bars9.LineStyle.Width = vg.Length(0)
	bars9.Color = plotutil.Color(1)
	bars9.Offset = 3.5 * w

	bars10, err := plotter.NewBarChart(group10, w)
	if err != nil {
		panic(err)
	}
	bars10.LineStyle.Width = vg.Length(0)
	bars10.Color = plotutil.Color(1)
	bars10.Offset = 4.5 * w

	// back bars
	backbars1, err := plotter.NewBarChart(backdrop1, w)
	if err != nil {
		panic(err)
	}
	backbars1.LineStyle.Width = vg.Length(0)
	backbars1.Color = plotutil.Color(1)
	backbars1.Offset = -4.5 * w

	backbars2, err := plotter.NewBarChart(backdrop2, w)
	if err != nil {
		panic(err)
	}
	backbars2.LineStyle.Width = vg.Length(0)
	backbars2.Color = plotutil.Color(1)
	backbars2.Offset = -3.5 * w

	backbars3, err := plotter.NewBarChart(backdrop3, w)
	if err != nil {
		panic(err)
	}
	backbars3.LineStyle.Width = vg.Length(0)
	backbars3.Color = plotutil.Color(1)
	backbars3.Offset = -2.5 * w

	backbars4, err := plotter.NewBarChart(backdrop4, w)
	if err != nil {
		panic(err)
	}
	backbars4.LineStyle.Width = vg.Length(0)
	backbars4.Color = plotutil.Color(1)
	backbars4.Offset = -1.5 * w

	backbars5, err := plotter.NewBarChart(backdrop5, w)
	if err != nil {
		panic(err)
	}
	backbars5.LineStyle.Width = vg.Length(0)
	backbars5.Color = plotutil.Color(1)
	backbars5.Offset = -0.5 * w

	backbars6, err := plotter.NewBarChart(backdrop6, w)
	if err != nil {
		panic(err)
	}
	backbars6.LineStyle.Width = vg.Length(0)
	backbars6.Color = plotutil.Color(1)
	backbars6.Offset = 0.5 * w

	backbars7, err := plotter.NewBarChart(backdrop7, w)
	if err != nil {
		panic(err)
	}
	backbars7.LineStyle.Width = vg.Length(0)
	backbars7.Color = plotutil.Color(1)
	backbars7.Offset = 1.5 * w

	backbars8, err := plotter.NewBarChart(backdrop8, w)
	if err != nil {
		panic(err)
	}
	backbars8.LineStyle.Width = vg.Length(0)
	backbars8.Color = plotutil.Color(1)
	backbars8.Offset = 2.5 * w

	backbars9, err := plotter.NewBarChart(backdrop9, w)
	if err != nil {
		panic(err)
	}
	backbars9.LineStyle.Width = vg.Length(0)
	backbars9.Color = plotutil.Color(1)
	backbars9.Offset = 3.5 * w

	backbars10, err := plotter.NewBarChart(backdrop10, w)
	if err != nil {
		panic(err)
	}
	backbars10.LineStyle.Width = vg.Length(0)
	backbars10.Color = plotutil.Color(1)
	backbars10.Offset = 4.5 * w

	p.Add(bars1, bars2, bars3, bars4, bars5, bars6, bars7, bars8, bars9, bars10, backbars1, backbars2, backbars3, backbars4, backbars5, backbars6, backbars7, backbars8, backbars9, backbars10)

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
