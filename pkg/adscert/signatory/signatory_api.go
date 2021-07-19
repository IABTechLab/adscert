package signatory

import (
	"github.com/IABTechLab/adscert/pkg/adscert/api"
)

type AuthenticatedConnectionsSignatory interface {
	SignAuthenticatedConnection(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error)
	VerifyAuthenticatedConnection(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error)
	VerifyAuthenticatedConnectionBatch(request *api.AuthenticatedConnectionVerificationBatchRequest) (*api.AuthenticatedConnectionVerificationBatchResponse, error)
}
