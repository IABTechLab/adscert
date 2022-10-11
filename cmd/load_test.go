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

	for key, iterationResult := range iterationResults {
		fmt.Printf("%v Signing Attempts: %v succeeded\n", key, iterationResult)
	}
	plotResults(iterationResults)
}

func plotResults(iterationResults map[int][]float64) {
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
	bars10.Offset = -4.5 * w

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
	p.Legend.Left = true

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
