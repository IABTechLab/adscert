package main

import (
	"flag"
	"strings"
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
)

type privateKeyFlags []string

func (i *privateKeyFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *privateKeyFlags) Set(value string) error {
	if value != "" {
		for _, v := range strings.Split(value, ",") {
			*i = append(*i, v)
		}
	}
	return nil
}

func main() {
	var privateKeys privateKeyFlags
	flag.Var(&privateKeys, "private_key", "base-64 encoded private key")

	if value := utils.GetEnvVarString("PRIVATE_KEY", ""); value != "" {
		for _, k := range strings.Split(value, ",") {
			privateKeys = append(privateKeys, k)
		}
	}

	flag.Parse()

	parsedLogLevel := logger.GetLevelFromString(*logLevel)
	logger.SetLevel(parsedLogLevel)
	logger.Infof("Log Level: %s, parsed as iota %v", *logLevel, parsedLogLevel)

	if len(privateKeys) == 0 {
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
	logger.Infof("Port: %v", *serverPort)

	grpcServer := grpc.NewServer()
	server.SetUpAdsCertSignatoryServer(grpcServer, *origin, *domainCheckInterval, *domainRenewalInterval, privateKeys)
	if err := server.StartServingRequests(grpcServer, *serverPort); err != nil {
		logger.Fatalf("gRPC server failure: %v", err)
	}
}
