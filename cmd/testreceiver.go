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
	"fmt"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// testreceiverCmd represents the test receivergit command
var (
	testreceiverCmd = &cobra.Command{
		Use:   "testreceiver",
		Short: "Run a simple local web server that will receive and verify requests",
		Run: func(cmd *cobra.Command, args []string) {
			startServer()
		},
	}
)

func init() {
	rootCmd.AddCommand(testreceiverCmd)
}

func startServer() {
	// API routes
	http.HandleFunc("/", func(w http.ResponseWriter, resp *http.Request) {
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		bodyString := string(bodyBytes)
		signatureMessage := resp.Header["X-Ads-Cert-Auth"][0]

		testverifyParams = &testverifyParameters{}
		testverifyParams.destinationURL = bodyString
		testverifyParams.signatureMessage = signatureMessage
		testverifyParams.serverAddress = "localhost:3000"
		testverifyParams.body = ""
		testverifyParams.verifyingTimeout = 5 * time.Millisecond

		fmt.Fprint(w, prototext.Format(verifyRequest(testverifyParams)))
	})

	port := ":5000"
	fmt.Println("Server is running on port" + port)
	log.Fatal(http.ListenAndServe(port, nil))
}
