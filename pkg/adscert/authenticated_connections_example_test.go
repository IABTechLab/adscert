package adscert_test

import (
	"fmt"
	"log"

	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
)

func ExampleAuthenticatedConnectionsSigner_SignAuthenticatedConnection() {
	adsCertCallsign := "origin-signer.com"
	signatory := adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(
		adsCertCallsign, adscertcrypto.GenerateFakePrivateKeysForTesting(adsCertCallsign), true)
	signer := adscert.NewAuthenticatedConnectionsSigner(signatory)

	// TODO: Add ability to seed PRNG for nonce and clock to generate deterministic results.
	signatory.SynchronizeForTesting("destination-verifier.com")

	// Determine the request parameters to sign.
	destinationURL := "https://ads.destination-verifier.com/request-ads"
	body := []byte("{'id': '12345'}")

	signature, err := signer.SignAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL: destinationURL,
			RequestBody:    body,
		})
	if err != nil {
		log.Fatal("unable to sign message: ", err)
	}

	fmt.Print("Signature passed via X-Ads-Cert-Auth: ", signature.SignatureMessages)
	// Output: Signature passed via X-Ads-Cert-Auth: [from=origin-signer.com&from_key=a1b2c3&invoking=destination-verifier.com&nonce=ZRC3FNU3skLS&status=0&timestamp=210426T163109&to=destination-verifier.com&to_key=a1b2c3; sigb=HLIYY-dTGn6D&sigu=Sbe5OWsUlFXU]

}

func ExampleAuthenticatedConnectionsSigner_VerifyAuthenticatedConnection() {
	adsCertCallsign := "destination-verifier.com"
	signatory := adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(
		adsCertCallsign, adscertcrypto.GenerateFakePrivateKeysForTesting(adsCertCallsign), true)
	signer := adscert.NewAuthenticatedConnectionsSigner(signatory)

	signatory.SynchronizeForTesting("origin-signer.com")

	// Determine the request parameters to sign.
	// Destination URL must be assembled by application based on path, HTTP Host header.
	// TODO: assemble sample code to show this based on HTTP package.
	destinationURL := "https://ads.destination-verifier.com/request-ads"
	body := []byte("{'id': '12345'}")
	messageToVerify := "from=origin-signer.com&from_key=a1b2c3&invoking=destination-verifier.com&nonce=ZRC3FNU3skLS&status=0&timestamp=210426T163109&to=destination-verifier.com&to_key=a1b2c3; sigb=HLIYY-dTGn6D&sigu=Sbe5OWsUlFXU"

	verification, err := signer.VerifyAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL:           destinationURL,
			RequestBody:              body,
			SignatureMessageToVerify: []string{messageToVerify},
		})
	if err != nil {
		log.Fatal("unable to verify message: ", err)
	}

	fmt.Printf("Signature verified? %v %v", verification.BodyValid, verification.URLValid)
	// Output: Signature verified? true true
}
