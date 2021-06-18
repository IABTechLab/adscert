package signatory

import (
	"github.com/IABTechLab/adscert/internal/api"
)

type AuthenticatedConnectionsSignatory interface {
	EmbossSigningPackage(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error)
	VerifySigningPackage(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error)
}
