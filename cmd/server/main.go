package main

import (
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/IABTechLab/adscert/pkg/adscert/server"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	serverPort            = flag.Int("server_port", 3000, "grpc server port")
	metricsPort           = flag.Int("metrics_port", 3001, "http metrics port")
	logLevel              = flag.String("loglevel", utils.GetEnvVarString("LOGLEVEL", ""), "minimum log verbosity")
	origin                = flag.String("origin", utils.GetEnvVarString("ORIGIN", ""), "ads.cert Call Sign domain name for this party's Signatory service deployment")
	domainCheckInterval   = flag.Duration("domain_check_interval", time.Duration(utils.GetEnvVarInt("DOMAIN_CHECK_INTERVAL", 30))*time.Second, "interval for checking domain records")
	domainRenewalInterval = flag.Duration("domain_renewal_interval", time.Duration(utils.GetEnvVarInt("DOMAIN_RENEWAL_INTERVAL", 300))*time.Second, "interval before considering domain records for renewal")
	privateKey            = flag.String("private_key", utils.GetEnvVarString("PRIVATE_KEY", ""), "base-64 encoded private key")
)

func main() {

	flag.Parse()
	logger.SetLevel(logger.GetLevelFromString(*logLevel))

	if *origin == "" {
		logger.Fatalf("Origin ads.cert Call Sign domain name is required")
	}

	if *privateKey == "" {
		logger.Fatalf("Private key is required")
	}

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		*origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		*domainCheckInterval,
		*domainRenewalInterval,
		[]string{*privateKey})

	grpcServer := grpc.NewServer()
	handler := &server.AdsCertSignatoryServer{
		SignatoryAPI: signatoryApi,
	}
	api.RegisterAdsCertSignatoryServer(grpcServer, handler)
	grpc_health_v1.RegisterHealthServer(grpcServer, handler)
	reflection.Register(grpcServer)

	logger.Infof("Starting AdsCert API server")
	logger.Infof("Origin ads.cert Call Sign domain: %v", *origin)
	logger.Infof("Port: %v", *serverPort)
	logger.Infof("Log Level: %v", *logLevel)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *serverPort))
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
		logger.Fatalf("Failed to serve GRPC: %v", err)
	}
}
