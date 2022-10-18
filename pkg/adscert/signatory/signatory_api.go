package signatory

import (
	"github.com/IABTechLab/adscert/pkg/adscert/api"
)

type AuthenticatedConnectionsSignatory interface {
	NoOperationResponse(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error)
	SignAuthenticatedConnection(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error)
	VerifyAuthenticatedConnection(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error)
}
