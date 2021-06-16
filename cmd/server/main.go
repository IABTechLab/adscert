package main

import (
	"context"
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"net"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/benbjohnson/clock"
	"google.golang.org/grpc"
)

var (
	port     = flag.Int("port", 3000, "grpc server port")
	logLevel = flag.String("loglevel", utils.GetEnvVar("LOGLEVEL"), "minimum log verbosity")
	origin   = flag.String("origin", utils.GetEnvVar("ORIGIN"), "ads.cert hostname for the originating party")
	signer   adscert.AuthenticatedConnectionsSigner
)

func main() {

	flag.Parse()
	logger.SetLevel(logger.GetLevelFromString(*logLevel))

	// TODO: using randomly generated test certs for now
	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*origin)

	if *origin == "" {
		logger.Fatalf("Origin hostname is required")
	}

	localSignatory := adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*origin, privateKeysBase64, false)
	signer = adscert.NewAuthenticatedConnectionsSigner(localSignatory, crypto_rand.Reader, clock.New())

	grpcServer := grpc.NewServer()
	api.RegisterAdsCertServer(grpcServer, &adsCertServer{})
	logger.Infof("Starting AdsCert API server")
	logger.Infof("Origin: %v", *origin)
	logger.Infof("Port: %v", *port)
	logger.Infof("Log Level: %v", *logLevel)

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		logger.Fatalf("Failed to open TCP: %v", err)
	}

	err = grpcServer.Serve(lis)
	if err != nil {
		logger.Fatalf("Failed to serve GRPC")
	}
}

type adsCertServer struct {
	api.UnimplementedAdsCertServer
}

func (s *adsCertServer) SignAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionSignatureParams) (*api.AuthenticatedConnectionSignature, error) {

	signature, err := signer.SignAuthenticatedConnection(adscert.AuthenticatedConnectionSignatureParams{
		DestinationURL: req.DestinationUrl,
		RequestBody:    req.RequestBody,
	})

	response := &api.AuthenticatedConnectionSignature{
		Signatures: signature.SignatureMessages,
	}

	return response, err
}

func (s *adsCertServer) VerifyAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionVerificationParams) (*api.AuthenticatedConnectionVerification, error) {

	verification, err := signer.VerifyAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL:           req.DestinationUrl,
			RequestBody:              req.RequestBody,
			SignatureMessageToVerify: req.Signatures,
		})

	response := &api.AuthenticatedConnectionVerification{
		BodyValid: verification.BodyValid,
		UrlValid:  verification.URLValid,
	}

	return response, err
}

// TODO: enforce interface
var _ api.AdsCertServer = &adsCertServer{}
