package main

import (
	"context"
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

var (
	serverPort   = flag.Int("server_port", 3000, "grpc server port")
	metricsPort  = flag.Int("metrics_port", 3001, "http metrics port")
	logLevel     = flag.String("loglevel", utils.GetEnvVar("LOGLEVEL"), "minimum log verbosity")
	origin       = flag.String("origin", utils.GetEnvVar("ORIGIN"), "ads.cert hostname for the originating party")
	signatoryApi signatory.AuthenticatedConnectionsSignatory
)

func main() {

	flag.Parse()
	logger.SetLevel(logger.GetLevelFromString(*logLevel))

	// TODO: using randomly generated test certs for now
	privateKeysBase64 := signatory.GenerateFakePrivateKeysForTesting(*origin)

	if *origin == "" {
		logger.Fatalf("Origin hostname is required")
		os.Exit(returnExitCode())
	}

	signatoryApi = signatory.NewLocalAuthenticatedConnectionsSignatory(*origin, crypto_rand.Reader, clock.New(), discovery.NewRealDnsResolver(), privateKeysBase64)

	grpcServer := grpc.NewServer()
	api.RegisterAdsCertSignatoryServer(grpcServer, &adsCertSignatoryServer{})
	logger.Infof("Starting AdsCert API server")
	logger.Infof("Origin: %v", *origin)
	logger.Infof("Port: %v", *serverPort)
	logger.Infof("Log Level: %v", *logLevel)

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *serverPort))
	if err != nil {
		logger.Fatalf("Failed to open TCP: %v", err)
	}
	go runServer(lis, grpcServer)

	logger.Info("Starting Metrics server")
	logger.Infof("Port: %v", *metricsPort)
	http.Handle("/metrics", promhttp.HandlerFor(metrics.GetAdscertMetricsRegistry(), promhttp.HandlerOpts{}))
	http.ListenAndServe(fmt.Sprintf(":%d", *metricsPort), nil)
}

func returnExitCode() int {
	return 1
}

func runServer(l net.Listener, s *grpc.Server) {
	err := s.Serve(l)
	if err != nil {
		logger.Fatalf("Failed to serve GRPC")
	}
}

type adsCertSignatoryServer struct {
	api.UnimplementedAdsCertSignatoryServer
}

func (s *adsCertSignatoryServer) SignAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error) {
	response, err := signatoryApi.SignAuthenticatedConnection(req)
	return response, err
}

func (s *adsCertSignatoryServer) VerifyAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {
	response, err := signatoryApi.VerifyAuthenticatedConnection(req)
	return response, err
}
