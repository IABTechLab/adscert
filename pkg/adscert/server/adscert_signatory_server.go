package server

import (
	"context"
	"errors"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type AdsCertSignatoryServer struct {
	api.UnimplementedAdsCertSignatoryServer

	SignatoryAPI *signatory.LocalAuthenticatedConnectionsSignatory
}

func (s *AdsCertSignatoryServer) SignAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error) {
	response, err := s.SignatoryAPI.SignAuthenticatedConnection(req)
	return response, err
}

func (s *AdsCertSignatoryServer) VerifyAuthenticatedConnection(ctx context.Context, req *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {
	response, err := s.SignatoryAPI.VerifyAuthenticatedConnection(req)
	return response, err
}

func (s *AdsCertSignatoryServer) Check(ctx context.Context, in *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	logger.Info("received health check request")
	if s.SignatoryAPI == nil {
		return &grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN,
		}, errors.New("signatoryApi not initialized")
	}
	status := grpc_health_v1.HealthCheckResponse_SERVING
	if !s.SignatoryAPI.IsHealthy() {
		status = grpc_health_v1.HealthCheckResponse_NOT_SERVING
	}
	return &grpc_health_v1.HealthCheckResponse{
		Status: status,
	}, nil
}

func (s *AdsCertSignatoryServer) Watch(r *grpc_health_v1.HealthCheckRequest, ws grpc_health_v1.Health_WatchServer) error {
	logger.Info("received health check request")
	if s.SignatoryAPI == nil {
		return ws.Send(&grpc_health_v1.HealthCheckResponse{
			Status: grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN,
		})
	}
	status := grpc_health_v1.HealthCheckResponse_SERVING
	if !s.SignatoryAPI.IsHealthy() {
		status = grpc_health_v1.HealthCheckResponse_NOT_SERVING
	}
	return ws.Send(&grpc_health_v1.HealthCheckResponse{
		Status: status,
	})
}
