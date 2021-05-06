package adscert

import (
	"github.com/IABTechLab/adscert_server/internal/adscert"
	"github.com/IABTechLab/adscert_server/internal/adscertcrypto"
)

type adsCertVerifier struct {
	domains  []string
	verifier adscert.AuthenticatedConnectionsSigner
}

func NewAdsCertVerifier(domains []string) adsCertVerifier {
	var av adsCertVerifier
	// TODO use domains to create allowlist of messages to verify
	// and domains to lookup
	av.domains = domains

	// TODO: Verify private keys are not needed on server side
	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(domains[0])

	// TODO: support multiple domains in dns resolver and assocaited keys
	av.verifier = adscert.NewAuthenticatedConnectionsSigner(
		adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(domains[0], privateKeysBase64, false))

	return av
}

func (av *adsCertVerifier) Verify(url string, body []byte, signatureHeaders []string) (adscert.AuthenticatedConnectionVerification, error) {

	// TODO Allowlist of domains here?
	return av.verifier.VerifyAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL:           url,
			RequestBody:              body,
			SignatureMessageToVerify: signatureHeaders,
		})

}

type adsCertSigner struct {
	signer adscert.AuthenticatedConnectionsSigner
}

func NewAdsCertSigner(privateKeys []string, originDomain string) *adsCertSigner {
	as := new(adsCertSigner)

	// TODO: Why is this take an array of keys?
	as.signer = adscert.NewAuthenticatedConnectionsSigner(
		adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(originDomain, privateKeys, false))

	return as
}

/*
destinationURL is a full url of the format:
(scheme)://(domain):[port](path)?(query_params)
http://ads.ad-exchange.tk:8090/request?param1=example&param2=another
requestBody is the whle request body passed in as a byte array
*/
func (as *adsCertSigner) Sign(destinationURL string, requestBody []byte) (adscert.AuthenticatedConnectionSignature, error) {

	return as.signer.SignAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL: destinationURL,
			RequestBody:    requestBody,
		})

}
