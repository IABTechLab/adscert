package main

import (
	"context"
	crypto_rand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

var (
	serverPort            = flag.Int("server_port", 3000, "grpc server port")
	metricsPort           = flag.Int("metrics_port", 3001, "http metrics port")
	logLevel              = flag.String("loglevel", utils.GetEnvVarString("LOGLEVEL", ""), "minimum log verbosity")
	origin                = flag.String("origin", utils.GetEnvVarString("ORIGIN", ""), "ads.cert hostname for the originating party")
	domainCheckInterval   = flag.Duration("domain_check_interval", time.Duration(utils.GetEnvVarInt("DOMAIN_CHECK_INTERVAL", 30))*time.Second, "interval for checking domain records")
	domainRenewalInterval = flag.Duration("domain_renewal_interval", time.Duration(utils.GetEnvVarInt("DOMAIN_RENEWAL_INTERVAL", 300))*time.Second, "interval before considering domain records for renewal")
	privateKey            = flag.String("private_key", utils.GetEnvVarString("PRIVATE_KEY", ""), "base-64 encoded private key")
	signatoryApi          *signatory.LocalAuthenticatedConnectionsSignatory
)

func main() {

	flag.Parse()
	logger.SetLevel(logger.GetLevelFromString(*logLevel))

	if *origin == "" {
		logger.Fatalf("Origin hostname is required")
		os.Exit(returnExitCode())
	}

	if *privateKey == "" {
		logger.Fatalf("Private key is required")
		os.Exit(returnExitCode())
	}

	signatoryApi = signatory.NewLocalAuthenticatedConnectionsSignatory(
		*origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		*domainCheckInterval,
		*domainRenewalInterval,
		[]string{*privateKey})

	grpcServer := grpc.NewServer()
	api.RegisterAdsCertSignatoryServer(grpcServer, &adsCertSignatoryServer{})
	logger.Infof("Starting AdsCert API server")
	logger.Infof("Origin: %v", *origin)
	logger.Infof("Port: %v", *serverPort)
	logger.Infof("Log Level: %v", *logLevel)

	grpc_health_v1.RegisterHealthServer(grpcServer, &adsCertSignatoryServer{})

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *serverPort))
	if err != nil {
		logger.Fatalf("Failed to open TCP: %v", err)
		os.Exit(returnExitCode())
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
		logger.Fatalf("Failed to serve GRPC: %v", err)
		os.Exit(returnExitCode())
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

func (s *adsCertSignatoryServer) Check(ctx context.Context, in *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	logger.Info("received health check request")
	if signatoryApi == nil {
		return &grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN,
		}, errors.New("signatoryApi not initialized")
	}
	status := grpc_health_v1.HealthCheckResponse_SERVING
	if !signatoryApi.IsHealthy() {
		status = grpc_health_v1.HealthCheckResponse_NOT_SERVING
	}
	return &grpc_health_v1.HealthCheckResponse{
		Status: status,
	}, nil
}

func (s *adsCertSignatoryServer) Watch(r *grpc_health_v1.HealthCheckRequest, ws grpc_health_v1.Health_WatchServer) error {
	logger.Info("received health check request")
	if signatoryApi == nil {
		return ws.Send(&grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN,
		})
	}
	status := grpc_health_v1.HealthCheckResponse_SERVING
	if !signatoryApi.IsHealthy() {
		status = grpc_health_v1.HealthCheckResponse_NOT_SERVING
	}
	return ws.Send(&grpc_health_v1.HealthCheckResponse{
		Status: status,
	})
}
