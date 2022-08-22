/*
Copyright © 2022 IAB Technology Laboratory, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"io/ioutil"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
	// "time"
	// "github.com/IABTechLab/adscert/pkg/adscert/api"
	// "github.com/IABTechLab/adscert/pkg/adscert/logger"
	// "github.com/IABTechLab/adscert/pkg/adscert/signatory"
	// "google.golang.org/grpc"
	// "google.golang.org/grpc/credentials/insecure"
	// "google.golang.org/protobuf/encoding/prototext"

	"fmt"
	"log"
	"net/http"
)

// testreceiverCmd represents the test receivergit command
var (
	testreceiverParams = &testreceiverParameters{}

	testreceiverCmd = &cobra.Command{
		Use:   "testreceiver",
		Short: "Run a simple local web server that will receive and verify requests",
		Run: func(cmd *cobra.Command, args []string) {
			startServer(testreceiverParams)
		},
	}
)

type testreceiverParameters struct {
}

func init() {
	rootCmd.AddCommand(testreceiverCmd)
}

func startServer(testreceiverParams *testreceiverParameters) {

	// API routes
	http.HandleFunc("/", func(w http.ResponseWriter, resp *http.Request) {
		// fmt.Fprintf(w, "Hello world from adscert")
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		bodyString := string(bodyBytes)
		signatureMessage := resp.Header["X-Ads-Cert-Auth"][0]

		// Print Statements
		// Note if you try to access a key in the map that doesn't exist you will get an error
		// a check on the key should be made to prevent this
		// this code isn't meant for production
		fmt.Fprint(w, "\n")
		fmt.Fprint(w, signatureMessage)
		fmt.Fprint(w, "\n")
		fmt.Fprint(w, "\n")
		fmt.Fprint(w, bodyString)
		fmt.Fprint(w, "\n")
		fmt.Fprint(w, "\n")

		testverifyParams = &testverifyParameters{}
		testverifyParams.destinationURL = bodyString
		testverifyParams.signatureMessage = signatureMessage
		fmt.Fprint(w, prototext.Format(verifyRequest(testverifyParams)))
	})

	http.HandleFunc("/hi", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hi")
	})

	port := ":5000"
	fmt.Println("Server is running on port" + port)

	// Start server on port specified above
	log.Fatal(http.ListenAndServe(port, nil))
}
