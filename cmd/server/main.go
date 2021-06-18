package main

import (
	"context"
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"net"
	"net/http"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/internal/metrics"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

var (
	serverPort  = flag.Int("server_port", 3000, "grpc server port")
	metricsPort = flag.Int("metrics_port", 3001, "http metrics port")
	logLevel    = flag.String("loglevel", utils.GetEnvVar("LOGLEVEL"), "minimum log verbosity")
	origin      = flag.String("origin", utils.GetEnvVar("ORIGIN"), "ads.cert hostname for the originating party")
	signatory   adscertcrypto.AuthenticatedConnectionsSignatory
)

func main() {

	flag.Parse()
	logger.SetLevel(logger.GetLevelFromString(*logLevel))

	// TODO: using randomly generated test certs for now
	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*origin)

	if *origin == "" {
		logger.Fatalf("Origin hostname is required")
	}

	signatory = adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*origin, crypto_rand.Reader, clock.New(), privateKeysBase64, false)

	grpcServer := grpc.NewServer()
	api.RegisterAdsCertServer(grpcServer, &adsCertServer{})
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

func runServer(l net.Listener, s *grpc.Server) {
	err := s.Serve(l)
	if err != nil {
		logger.Fatalf("Failed to serve GRPC")
	}
}

type adsCertServer struct {
	api.UnimplementedAdsCertServer
}

func (s *adsCertServer) SignAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error) {
	response, err := signatory.EmbossSigningPackage(req)
	return response, err
}

func (s *adsCertServer) VerifyAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {
	response, err := signatory.VerifySigningPackage(req)
	return response, err
}
