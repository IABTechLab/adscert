package adscert

import (
	"io"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
)

// AuthenticatedConnectionsSigner generates a signature intended for the
// specified party over the specified message.
type AuthenticatedConnectionsSigner interface {
	SignAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionSignature, error)

	VerifyAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionVerification, error)
	VerifyAuthenticatedConnectionWithPackage(params adscertcrypto.AuthenticatedConnectionVerificationPackage) (AuthenticatedConnectionVerification, error)
}

// NewAuthenticatedConnectionsSigner creates a new signer instance for creating
// ads.cert Authenticated Connections signatures.
func NewAuthenticatedConnectionsSigner(signatory adscertcrypto.AuthenticatedConnectionsSignatory, reader io.Reader) AuthenticatedConnectionsSigner {
	return &authenticatedConnectionsSigner{
		signatory:    signatory,
		secureRandom: reader,
	}
}

// AuthenticatedConnectionSignatureParams captures parameters for the
// SignAuthenticatedConnection operation.
type AuthenticatedConnectionSignatureParams struct {
	DestinationURL string
	RequestBody    []byte

	// Curtis notes:
	// For offline verification, we need to have this message have the option to pass in the
	// hash of the URL and request body. We probably want to include a utility function somewhere
	// that generates these hashes in a consistent fashion.  I don't know if it is better to have
	// that output the hash as raw bytes or base64 encoded... maybe the API provides the option
	// to choose which variant is easier to work with depending on the logging technique they use.

	// When verifying an existing set of signatures, also include these values.
	SignatureMessageToVerify []string

	// optional field to pass as custom time.
	CustomTime func() time.Time
}

// AuthenticatedConnectionSignature represents a signature conforming to the
// ads.cert Authenticated Connections specification. Multiple signatures may be
// present for integrations that utilize a third-party verification service or
// similar multiparty integration.
type AuthenticatedConnectionSignature struct {
	SignatureMessages []string

	// Curtis notes:
	// See AuthenticatedConnectionVerification below for notes about signature metadata. We'll want
	// to expose structured data about the outcomes of signing operations so that the integrator
	// can use that information for monitoring and analytics (e.g. monitoring the distribution
	// of signature outcome status codes.)
}

// AuthenticatedConnectionVerification captures the results of verifying a
// signature against the ads.cert Authenticated Connections specification
// requirements.
type AuthenticatedConnectionVerification struct {
	BodyValid bool
	URLValid  bool

	// Curtis notes:
	// We need to determine what additional structured metadata we want to return from verification
	// invocations looks like (keeping in mind that this needs to be ported to all other integrator
	// languages).
	//
	// Because multiple signatures could appear in a request according to the spec, the interpreted
	// representation of the signatures needs to be provided as a list (slice).
	//
	// Potential candidates include:
	// * FromDomain string
	// * FromKey string (useful for analytics regarding key vintage distribution)
	// * SignatureTimestamp time.Time (the parsed timestamp found in the signature message)
	// * SignatureNonce string (useful for verifier de-duplicating signatures)
	// * SignerStatus (a language-specific representation of the status provided in the signature
	//   message in an enum-like format)
	// * VerificationOutcome (enum-like representation of the verification outcome, possibly akin
	//   to the "Err" codes in formats/adscert_connection_signature.go)
	// * ToKey string (useful for analytics regarding key vintage distribution, e.g. knowing when
	//   it's safe to rotate keys)
	// * ToDomain, InvokingDomain string (useful in identifying signatures meant for other parties)
	//
	// ToDomain and InvokingDomain are probably redundant and not useful to an integrator app in
	// the most basic case, but it would be useful for giving feedback to integrators if there
	// are multiple signatures present on the request or if the signature destination isn't the
	// intended party.
	//
	// We might also want to provide latency metrics in the response, but this can be added later.
}
