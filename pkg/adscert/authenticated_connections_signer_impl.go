package adscert

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
)

type authenticatedConnectionsSigner struct {
	secureRandom io.Reader

	signatory adscertcrypto.AuthenticatedConnectionsSignatory
}

func (c *authenticatedConnectionsSigner) SignAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionSignature, error) {
	var err error
	response := AuthenticatedConnectionSignature{}
	signatureRequest := adscertcrypto.AuthenticatedConnectionSigningPackage{}

	// if custom time function exists in params
	customTime := params.CustomTime
	if customTime == nil {
		// otherwise fall back to original time.Now function
		customTime = time.Now
	}
	signatureRequest.Timestamp = customTime().UTC().Format("060102T150405")

	if signatureRequest.Nonce, err = c.generateNonce(); err != nil {
		return response, err
	}

	if err = assembleRequestInfo(&params, &signatureRequest.RequestInfo); err != nil {
		return response, fmt.Errorf("error parsing request URL: %v", err)
	}

	// Invoke the embossing service
	embossReply, err := c.signatory.EmbossSigningPackage(&signatureRequest)
	if err != nil {
		return response, fmt.Errorf("error embossing signing package: %v", err)
	}

	response.SignatureMessages = embossReply.SignatureMessages

	return response, nil
}
func (c *authenticatedConnectionsSigner) VerifyAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionVerification, error) {

	response := AuthenticatedConnectionVerification{}
	verificationRequest := adscertcrypto.AuthenticatedConnectionVerificationPackage{}

	if err := assembleRequestInfo(&params, &verificationRequest.RequestInfo); err != nil {
		return response, fmt.Errorf("error parsing request URL: %v", err)
	}

	// TODO: change this so that the verification request can pass multiple signature messages.
	// Let the signatory pick through the multiple messages (if present) and figure out what
	// to do with them.
	verificationRequest.SignatureMessage = params.SignatureMessageToVerify[0]

	verifyReply, err := c.signatory.VerifySigningPackage(&verificationRequest)
	if err != nil {
		return response, fmt.Errorf("error verifying signing package: %v", err)
	}

	response.BodyValid = verifyReply.BodyValid
	response.URLValid = verifyReply.URLValid

	return response, nil
}

func (c *authenticatedConnectionsSigner) VerifyAuthenticatedConnectionWithPackage(verificationRequest adscertcrypto.AuthenticatedConnectionVerificationPackage) (AuthenticatedConnectionVerification, error) {

	response := AuthenticatedConnectionVerification{}

	verifyReply, err := c.signatory.VerifySigningPackage(&verificationRequest)
	if err != nil {
		return response, fmt.Errorf("error verifying signing package: %v", err)
	}

	response.BodyValid = verifyReply.BodyValid
	response.URLValid = verifyReply.URLValid

	return response, nil
}

func assembleRequestInfo(params *AuthenticatedConnectionSignatureParams, requestInfo *adscertcrypto.RequestInfo) error {
	parsedURL, tldPlusOne, err := utils.ParseURLComponents(params.DestinationURL)
	if err != nil {
		// TODO: switch to using a named error message indicating URL parse failure.
		return fmt.Errorf("unable to parse destination URL: %v", err)
	}

	requestInfo.InvocationHostname = tldPlusOne

	urlHash := sha256.Sum256([]byte(parsedURL.String()))
	copy(requestInfo.URLHash[:], urlHash[:])

	bodyHash := sha256.Sum256(params.RequestBody)
	copy(requestInfo.BodyHash[:], bodyHash[:])

	return nil
}

func (c *authenticatedConnectionsSigner) generateNonce() (string, error) {
	var nonce [32]byte
	n, err := io.ReadFull(c.secureRandom, nonce[:])
	if err != nil {
		return "", fmt.Errorf("error generating random: %v", err)
	}
	if n != 32 {
		return "", fmt.Errorf("unexpected number of random values: %d", n)
	}
	return formats.B64truncate(nonce[:], 12), nil
}
