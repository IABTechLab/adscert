package adscert

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/metrics"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/benbjohnson/clock"
)

type authenticatedConnectionsSigner struct {
	secureRandom io.Reader
	clock        clock.Clock

	signatory adscertcrypto.AuthenticatedConnectionsSignatory
}

func (c *authenticatedConnectionsSigner) SignAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionSignature, error) {

	var err error
	response := AuthenticatedConnectionSignature{}
	signatureRequest := &api.AuthenticatedConnectionSigningPackage{}

	signatureRequest.Timestamp = c.clock.Now().UTC().Format("060102T150405")

	if signatureRequest.Nonce, err = c.generateNonce(); err != nil {
		metrics.RecordSigningMetrics(metrics.SignErrorGenerateNonce)
		return response, err
	}

	if err = assembleRequestInfo(&params, signatureRequest.RequestInfo); err != nil {
		metrics.RecordSigningMetrics(metrics.SignErrorParseUrl)
		return response, fmt.Errorf("error parsing request URL: %v", err)
	}

	// Invoke the embossing service
	embossReply, err := c.signatory.EmbossSigningPackage(signatureRequest)
	if err != nil {
		metrics.RecordSigningMetrics(metrics.SignErrorEmboss)
		return response, fmt.Errorf("error embossing signing package: %v", err)
	}

	// Enumerate the signature messages in an easy-to-use slice that the
	// integrating application can put into the HTTP header message in one line.
	for _, si := range embossReply.SignatureInfo {
		response.SignatureMessages = append(response.SignatureMessages, si.SignatureMessage)
	}

	// Provide structured metadata about the signing operation.
	response.SignatureInfo = embossReply.SignatureInfo

	metrics.RecordSigningMetrics(metrics.SignErrorNone)

	return response, nil
}

func (c *authenticatedConnectionsSigner) VerifyAuthenticatedConnection(params AuthenticatedConnectionSignatureParams) (AuthenticatedConnectionVerification, error) {

	response := AuthenticatedConnectionVerification{}
	verificationRequest := api.AuthenticatedConnectionVerificationPackage{}

	if err := assembleRequestInfo(&params, verificationRequest.RequestInfo); err != nil {
		metrics.RecordVerifyMetrics(metrics.VerifyErrorParseUrl)
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

	metrics.RecordVerifyMetrics(metrics.VerifyErrorNone)

	response.BodyValid = verifyReply.BodyValid
	metrics.RecordVerifyResultMetrics(metrics.VerifyResultTypeBody, verifyReply.BodyValid)
	response.URLValid = verifyReply.UrlValid
	metrics.RecordVerifyResultMetrics(metrics.VerifyResultTypeUrl, verifyReply.UrlValid)

	return response, nil
}

func assembleRequestInfo(params *AuthenticatedConnectionSignatureParams, requestInfo *api.RequestInfo) error {
	var parsedURL *url.URL

	if params.InvocationHostname == "" {
		var tldPlusOne string
		var err error

		parsedURL, tldPlusOne, err = utils.ParseURLComponents(params.DestinationURL)
		if err != nil {
			// TODO: switch to using a named error message indicating URL parse failure.
			return fmt.Errorf("unable to parse destination URL: %v", err)
		}
		requestInfo.InvocationHostname = tldPlusOne
	} else {
		requestInfo.InvocationHostname = params.InvocationHostname
	}

	if params.HashedDestinationURL != nil {
		requestInfo.UrlHash = *params.HashedDestinationURL
	} else {
		urlHash := sha256.Sum256([]byte(parsedURL.String()))
		copy(requestInfo.UrlHash[:], urlHash[:])
	}

	if params.HashedRequestBody != nil {
		requestInfo.BodyHash = *params.HashedRequestBody
	} else {
		bodyHash := sha256.Sum256(params.RequestBody)
		copy(requestInfo.BodyHash[:], bodyHash[:])
	}

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
