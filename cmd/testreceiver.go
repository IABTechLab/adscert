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
	"github.com/spf13/cobra"
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
	url string
}

func init() {
	rootCmd.AddCommand(testreceiverCmd)

	testreceiverCmd.Flags().StringVar(&testreceiverParams.url, "url", "", "URL to invoke")
}

func startServer(testreceiverParams *testreceiverParameters) {
	print(testreceiverParams.url)

	// API routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello world from adscert")
	})
	http.HandleFunc("/hi", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hi")
	})

	port := ":5000"
	fmt.Println("Server is running on port" + port)

	// Start server on port specified above
	log.Fatal(http.ListenAndServe(port, nil))
}
