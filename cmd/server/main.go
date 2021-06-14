package main

import (
	"context"
	crypto_rand "crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/IABTechLab/adscert/cmd/internal/api"
	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/benbjohnson/clock"
	"google.golang.org/grpc"
)

var (
	port           = flag.Int("port", 3000, "GRPC server port")
	originCallsign = flag.String("origin_callsign", "", "ads.cert callsign for the originating party")
	signer         adscert.AuthenticatedConnectionsSigner
)

func main() {

	flag.Parse()

	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*originCallsign)
	signer = adscert.NewAuthenticatedConnectionsSigner(
		adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*originCallsign, privateKeysBase64, false), crypto_rand.Reader, clock.New())

	log.Printf("Starting AdsCert API server...")

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	srv := &adsCertServer{}
	api.RegisterAdsCertServer(grpcServer, srv)

	err = grpcServer.Serve(lis)
	if err != nil {
		log.Fatalf("Failed to serve GRPC")
	}

}

type adsCertServer struct {
	api.UnimplementedAdsCertServer
}

func (s *adsCertServer) SignAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionSignatureParams) (*api.AuthenticatedConnectionSignature, error) {
	signer.SignAuthenticatedConnection(adscert.AuthenticatedConnectionSignatureParams{
		DestinationURL: req.DestinationUrl,
		RequestBody:    []byte(req.RequestBody),
	})
	return &api.AuthenticatedConnectionSignature{}, nil
}

func (s *adsCertServer) VerifyAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionSignatureParams) (*api.AuthenticatedConnectionVerification, error) {
	// TODO: replace stub
	return &api.AuthenticatedConnectionVerification{}, nil
}

// TODO: enforce interface
var _ api.AdsCertServer = &adsCertServer{}
