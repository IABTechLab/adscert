package main

import (
	"flag"
	"time"

	"github.com/IABTechLab/adscert/internal/server"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"google.golang.org/grpc"
)

var (
	serverPort            = flag.Int("server_port", 3000, "grpc server port")
	metricsPort           = flag.Int("metrics_port", 3001, "http metrics port")
	logLevel              = flag.String("loglevel", utils.GetEnvVarString("LOGLEVEL", "INFO"), "minimum log verbosity")
	origin                = flag.String("origin", utils.GetEnvVarString("ORIGIN", ""), "ads.cert Call Sign domain name for this party's Signatory service deployment")
	domainCheckInterval   = flag.Duration("domain_check_interval", time.Duration(utils.GetEnvVarInt("DOMAIN_CHECK_INTERVAL", 30))*time.Second, "interval for checking domain records")
	domainRenewalInterval = flag.Duration("domain_renewal_interval", time.Duration(utils.GetEnvVarInt("DOMAIN_RENEWAL_INTERVAL", 300))*time.Second, "interval before considering domain records for renewal")
	privateKey            = flag.String("private_key", utils.GetEnvVarString("PRIVATE_KEY", ""), "base-64 encoded private key")
)

func main() {

	flag.Parse()

	parsedLogLevel := logger.GetLevelFromString(*logLevel)
	logger.SetLevel(parsedLogLevel)
	logger.Infof("Log Level: %s, parsed as iota %v", *logLevel, parsedLogLevel)

	if *privateKey == "" {
		logger.Fatalf("Private key is required")
	}

	logger.Info("Starting Metrics server")
	logger.Infof("Port: %v", *metricsPort)
	go func() {
		if err := server.StartMetricsServer(*metricsPort); err != nil {
			logger.Fatalf("Error trying to run metrics server: %v", err)
		}
	}()

	logger.Infof("Starting AdsCert API server")
	logger.Infof("Origin ads.cert Call Sign domain: %v", *origin)
	logger.Infof("Port: %v", *serverPort)

	grpcServer := grpc.NewServer()
	server.SetUpAdsCertSignatoryServer(grpcServer, *origin, *domainCheckInterval, *domainRenewalInterval, []string{*privateKey})
	if err := server.StartServingRequests(grpcServer, *serverPort); err != nil {
		logger.Fatalf("gRPC server failure: %v", err)
	}
}
