package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	serverAddress  = flag.String("server_address", "localhost:3000", "address of grpc server")
	destinationURL = flag.String("url", "https://google.com/gen_204", "URL to invoke")
	body           = flag.String("body", "", "POST request body")
)

func main() {
	flag.Parse()

	// create grpc connection for client to use
	// options here use insecure defaults
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial(*serverAddress, opts...)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Optional: performs a health check against the server before actually
	// trying to invoke the signatory service.
	performHealthCheck(conn)

	clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: 3 * time.Second}
	signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, *destinationURL, []byte(*body))

	logger.Infof("signing request for url: %v", *destinationURL)
	signatureResponse, err := signatoryClient.SignAuthenticatedConnection(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
		})

	if err != nil {
		logger.Warningf("unable to sign message: %v", err)
	}

	if signatureResponse != nil && signatureResponse.RequestInfo != nil {
		logger.Infof("signature response:\n%s", prototext.Format(signatureResponse))
	} else {
		logger.Warningf("signature response is missing")
	}
}

func performHealthCheck(conn *grpc.ClientConn) {
	hctx, hcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer hcancel()
	healthClient := grpc_health_v1.NewHealthClient(conn)
	healthCheckResponse, err := healthClient.Check(hctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		log.Fatalf("Failed to pass heath check: %v", err)
	}
	if healthCheckResponse.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		log.Fatalf("Failed to pass heath status: %v", healthCheckResponse.Status)
	}
}
