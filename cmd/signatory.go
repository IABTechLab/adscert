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
	"time"

	"github.com/IABTechLab/adscert/internal/server"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

// signatoryCmd represents the signatory command
var (
	signatoryCmd = &cobra.Command{
		Use:   "signatory",
		Short: "Runs a gRPC server with ads.cert signing/verification capabilities.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("signatory called, listening on %d and monitoring %d\n", signatoryParams.serverPort, signatoryParams.metricsPort)
			signatoryStart(signatoryParams)
		},
	}

	signatoryParams = &signatoryParameters{}
)

type signatoryParameters struct {
	serverPort  int
	metricsPort int

	domainCheckInterval   time.Duration
	domainRenewalInterval time.Duration

	// deprecated flags
	origin     string
	privateKey string
}

func init() {
	rootCmd.AddCommand(signatoryCmd)

	signatoryCmd.Flags().IntVar(&signatoryParams.serverPort, "server_port", 3000, "gRPC server will listen on this TCP port number")
	signatoryCmd.Flags().IntVar(&signatoryParams.metricsPort, "metrics_port", 3001, "Server will expose monitoring on this TCP port via an HTTP server.")

	signatoryCmd.Flags().DurationVar(&signatoryParams.domainCheckInterval, "domain_check_interval", 30*time.Second, "interval for checking domain records")
	signatoryCmd.Flags().DurationVar(&signatoryParams.domainRenewalInterval, "domain_renewal_interval", 300*time.Second, "interval before considering domain records for renewal")

	signatoryCmd.Flags().StringVar(&signatoryParams.origin, "origin", "", "ads.cert Call Sign domain name for this party's Signatory service deployment")
	signatoryCmd.Flags().StringVar(&signatoryParams.privateKey, "private_key", "", "base-64 encoded private key")
}

func signatoryStart(signatoryParams *signatoryParameters) error {

	// Change to errgroup.WithContext() if any subsequent changes require
	// accepting a context.Context as a parameter.
	g := errgroup.Group{}

	g.Go(func() error {
		return server.StartMetricsServer(signatoryParams.metricsPort)
	})

	g.Go(func() error {
		grpcServer := grpc.NewServer()
		server.SetUpAdsCertSignatoryServer(
			grpcServer,
			signatoryParams.origin,
			signatoryParams.domainCheckInterval,
			signatoryParams.domainRenewalInterval,
			[]string{signatoryParams.privateKey})
		return server.StartServingRequests(grpcServer, signatoryParams.serverPort)
	})

	return g.Wait()
}
