package signatory_test

import (
	"fmt"
	"log"
	"math/rand"
	"testing"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
)

func setupSignatory(adsCertCallsign string) signatory.AuthenticatedConnectionsSignatory {

	// fixed time for testing
	mockClock := clock.NewMock()
	mockClock.Set(time.Date(2001, time.January, 1, 1, 1, 1, 1, time.UTC))

	// set seed to 0 to retrieve deterministic random reader
	randomReader := rand.New(rand.NewSource(0))

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(adsCertCallsign)

	signatory := signatory.NewLocalAuthenticatedConnectionsSignatory(
		adsCertCallsign,
		randomReader,
		mockClock,
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(30*time.Second), // domain check interval
		time.Duration(30*time.Second), // domain renewal interval
		base64PrivateKeys)

	return signatory
}

func TestSignAuthenticatedConnection(t *testing.T) {

	adsCertCallsign := "origin-signer.com"
	localSignatory := setupSignatory(adsCertCallsign)

	// Determine the request parameters to sign.
	destinationURL := "https://ads.destination-verifier.com/request-ads"
	body := []byte("{'id': '12345'}")

	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, destinationURL, body)

	signature, err := localSignatory.SignAuthenticatedConnection(&api.AuthenticatedConnectionSignatureRequest{
		RequestInfo: reqInfo,
		Timestamp:   "",
		Nonce:       "",
	})

	if err != nil {
		log.Fatal("unable to sign message: ", err)
	}

	fmt.Printf("Signature passed via X-Ads-Cert-Auth: %s\n\n", signatory.GetSignatures(signature))
	fmt.Printf("Structured metadata: %s\n", signature.RequestInfo.SignatureInfo[0])
}

func TestVerifyAuthenticatedConnection(t *testing.T) {

	adsCertCallsign := "destination-verifier.com"
	localSignatory := setupSignatory(adsCertCallsign)

	destinationURL := "https://ads.destination-verifier.com/request-ads"
	body := []byte("{'id': '12345'}")
	messageToVerify := "from=origin-signer.com&from_key=r-BSNk&invoking=destination-verifier.com&nonce=0MrwlrWfFd8M&status=0&timestamp=210601T145830&to=destination-verifier.com&to_key=i-HvLK; sigb=gbGVdxLF8w0L&sigu=PtcBVz_6JUlP"

	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, destinationURL, body)
	signatory.SetRequestSignatures(reqInfo, []string{messageToVerify})

	verification, err := localSignatory.VerifyAuthenticatedConnection(&api.AuthenticatedConnectionVerificationRequest{
		RequestInfo: []*api.RequestInfo{reqInfo},
	})

	if err != nil {
		log.Fatal("unable to verify message: ", err)
	}

	fmt.Printf("verification operation status: %v, signature decode status: %v", verification.VerificationOperationStatus, verification.VerificationInfo[0].SignatureDecodeStatus)
}
