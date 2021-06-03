package adscert

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"golang.org/x/net/publicsuffix"
)

type authenticatedConnectionsSigner struct {
	secureRandom io.Reader

	signatory adscertcrypto.AuthenticatedConnectionsSignatory
}

func (c *authenticatedConnectionsSigner) SignAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionSignature, error) {
	var err error
	response := AuthenticatedConnectionSignature{}
	signatureRequest := adscertcrypto.AuthenticatedConnectionSigningPackage{}

	// TODO Force to UTC
	signatureRequest.Timestamp = time.Now().Format("060102T150405")

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
	verificationRequest.SignatureMessage = params.SignatureMessageToVerify[0] // TODO fix me

	verifyReply, err := c.signatory.VerifySigningPackage(&verificationRequest)
	if err != nil {
		return response, fmt.Errorf("error verifying signing package: %v", err)
	}

	response.BodyValid = verifyReply.BodyValid
	response.URLValid = verifyReply.URLValid

	return response, nil
}

func assembleRequestInfo(params *AuthenticatedConnectionSignatureParams, requestInfo *adscertcrypto.RequestInfo) error {
	parsedURL, tldPlusOne, err := parseURLComponents(params.DestinationURL)
	if err != nil {
		// TODO: generate a signature message indicating URL parse failure.
		return fmt.Errorf("unable to parse destination URL: %v", err)
	}

	requestInfo.InvocationHostname = tldPlusOne

	urlHash := sha256.Sum256([]byte(parsedURL.String()))
	copy(requestInfo.URLHash[:], urlHash[:])

	bodyHash := sha256.Sum256(params.RequestBody)
	copy(requestInfo.BodyHash[:], bodyHash[:])

	return nil
}

func parseURLComponents(destinationURL string) (*url.URL, string, error) {
	parsedDestURL, err := url.Parse(destinationURL)
	if err != nil {
		return nil, "", err
	}
	tldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(parsedDestURL.Hostname())
	if err != nil {
		return nil, "", err
	}
	return parsedDestURL, tldPlusOne, nil
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
