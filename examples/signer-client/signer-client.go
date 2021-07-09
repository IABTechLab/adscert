package main

import (
	"flag"
	"log"
	"time"

	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc"
)

var (
	serverAddress  = flag.String("server_address", "localhost:3000", "address of grpc server")
	destinationURL = flag.String("url", "https://google.com/gen_204", "URL to invoke")
	body           = flag.String("body", "", "POST request body")
)

func main() {

	// create grpc connection for client to use
	// options here use insecure defaults
	opts := []grpc.DialOption{grpc.WithInsecure()}
	conn, err := grpc.Dial(*serverAddress, opts...)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	clientOpts := &signatory.AuthenticatedConnectionsSignatoryClientOptions{Timeout: 3 * time.Second}
	signatoryClient := signatory.NewAuthenticatedConnectionsSignatoryClient(conn, clientOpts)

	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, *destinationURL, []byte(*body))

	logger.Infof("signing request for url: %v", *destinationURL)
	signatureResponse, err := signatoryClient.SignAuthenticatedConnection(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
			Timestamp:   "",
			Nonce:       "",
		})

	if err != nil {
		logger.Warningf("unable to sign message: %v", err)
	}

	for _, si := range signatureResponse.SignatureInfo {
		logger.Infof("signature: %v", si.SignatureMessage)
	}

}
