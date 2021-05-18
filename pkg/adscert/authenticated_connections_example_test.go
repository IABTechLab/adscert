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
	//
	// Curtis notes:
	// 
	// # Clock interface
	// We can either use an existing project such as https://github.com/benbjohnson/clock to
	// provide this interface, or we can provide our own interface.  There are two areas where
	// the existing project could be useful:
	//
	// 1) providing an interface for Clock.Now() to inject a stable timestamp generator.
	// 2) providing an interface to obtain a mockable Ticker that can be programmatically
	//    triggered.
	//
	// Since the benbjohnson/clock module doesn't depend on any other modules, I'm inclined
	// to say that this would be OK to include.
	//	
	// # PRNG seed or mock PRNG
	// See the "crypto/rand" package.
	// Reader is a global, shared instance of a cryptographically secure random number generator
	// and is an instance of io.Reader.  It can be overwritten with a reference to an alternative
	// implementation (which seems to be frightfully insecure and one of the reasons why supply
	// chain attacks are an important risk to mitigate). 
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
	// See examples/verifier/example-verifier.go for more details on how to construct this URL.
	// Obtaining the invoked hostname may be impacted by reverse proxy servers, load balancing
	// software, CDNs, or other middleware solutions, so some experimentation may be needed
	// to customize URL reconstruction within your environment.
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
