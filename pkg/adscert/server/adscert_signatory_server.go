package server

import (
	"context"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
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
