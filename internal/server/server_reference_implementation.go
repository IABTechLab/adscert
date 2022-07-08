package server

import (
	crypto_rand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

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

func SetUpAdsCertSignatoryServer(grpcServer *grpc.Server, adscertCallSign string, domainCheckInterval time.Duration, domainRenewalInterval time.Duration, privateKeys []string) {
	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		adscertCallSign,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		domainCheckInterval,
		domainRenewalInterval,
		privateKeys)

	logger.Debugf("Origin ads.cert Call Sign domains: %v", strings.Join(signatoryApi.GetOriginCallsigns(), ","))

	handler := &server.AdsCertSignatoryServer{
		SignatoryAPI: signatoryApi,
	}
	api.RegisterAdsCertSignatoryServer(grpcServer, handler)
	grpc_health_v1.RegisterHealthServer(grpcServer, handler)
	reflection.Register(grpcServer)
}

func StartServingRequests(grpcServer *grpc.Server, serverPort int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", serverPort))
	if err != nil {
		return fmt.Errorf("error listening on TCP for gRPC server: %v", err)
	}

	// Start server and block indefinitely.
	if err = grpcServer.Serve(listener); err != nil {
		return fmt.Errorf("error serving gRPC: %v", err)
	}

	return nil
}

func StartMetricsServer(metricsPort int) error {
	http.Handle("/metrics", promhttp.HandlerFor(metrics.GetAdscertMetricsRegistry(), promhttp.HandlerOpts{}))
	err := http.ListenAndServe(fmt.Sprintf(":%d", metricsPort), nil)

	// Ignore normal shutdown errors.
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
