package signatory

import (
	"context"
	"time"

	"github.com/IABTechLab/adscert/internal/api"
	"google.golang.org/grpc"
)

func NewAuthenticatedConnectionsSignatoryClient(conn *grpc.ClientConn, options *AuthenticatedConnectionsSignatoryClientOptions) AuthenticatedConnectionsSignatory {

	grpcClient := api.NewAdsCertSignatoryClient(conn)

	return &AuthenticatedConnectionsSignatoryClient{
		grpcClient: grpcClient,
		timeout:    options.Timeout,
	}
}

type AuthenticatedConnectionsSignatoryClientOptions struct {
	Timeout time.Duration
}

type AuthenticatedConnectionsSignatoryClient struct {
	grpcClient api.AdsCertSignatoryClient

	timeout time.Duration
}

func (sc *AuthenticatedConnectionsSignatoryClient) SignAuthenticatedConnection(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error) {

	// set network call context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), sc.timeout)
	defer cancel()

	response, err := sc.grpcClient.SignAuthenticatedConnection(ctx, request)
	return response, err
}

func (sc *AuthenticatedConnectionsSignatoryClient) VerifyAuthenticatedConnection(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {

	// set network call context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), sc.timeout)
	defer cancel()

	response, err := sc.grpcClient.VerifyAuthenticatedConnection(ctx, request)
	return response, err
}
