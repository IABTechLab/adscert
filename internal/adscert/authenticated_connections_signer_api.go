package adscert

import (
	crypto_rand "crypto/rand"

	"github.com/IABTechLab/adscert_server/internal/adscertcrypto"
)

// AuthenticatedConnectionsSigner generates a signature intended for the
// specified party over the specified message.
type AuthenticatedConnectionsSigner interface {
	SignAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionSignature, error)

	VerifyAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionVerification, error)
}

// NewAuthenticatedConnectionsSigner creates a new signer instance for creating
// ads.cert Authenticated Connections signatures.
func NewAuthenticatedConnectionsSigner(signatory adscertcrypto.AuthenticatedConnectionsSignatory) AuthenticatedConnectionsSigner {
	return &authenticatedConnectionsSigner{
		signatory:    signatory,
		secureRandom: crypto_rand.Reader,
	}
}

// AuthenticatedConnectionSignatureParams captures parameters for the
// SignAuthenticatedConnection operation.
type AuthenticatedConnectionSignatureParams struct {
	DestinationURL string
	RequestBody    []byte

	// When verifying an existing set of signatures, also include these values.
	SignatureMessageToVerify []string
}

// AuthenticatedConnectionSignature represents a signature conforming to the
// ads.cert Authenticated Connections specification. Multiple signatures may be
// present for integrations that utilize a third-party verification service or
// similar multiparty integration.
type AuthenticatedConnectionSignature struct {
	SignatureMessages []string
}

// AuthenticatedConnectionVerification captures the results of verifying a
// signature against the ads.cert Authenticated Connections specification
// requirements.
type AuthenticatedConnectionVerification struct {
	// TODO: something more informative.
	BodyValid bool
	URLValid  bool
}
