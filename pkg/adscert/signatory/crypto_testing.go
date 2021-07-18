package signatory

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func GenerateFakePrivateKeysForTesting(adscertCallsign string) []string {
	_, primaryPrivateKey := GenerateFakeKeyPairFromDomainNameForTesting("_delivery._adscert." + adscertCallsign)
	return []string{
		base64.RawURLEncoding.EncodeToString(primaryPrivateKey[:]),
	}
}

func GenerateFakeAdsCertRecordForTesting(adscertCallsign string) string {
	primaryPublicKey, _ := GenerateFakeKeyPairFromDomainNameForTesting(adscertCallsign)
	return fmt.Sprintf("v=adcrtd k=x25519 h=sha256 p=%s",
		base64.RawURLEncoding.EncodeToString(primaryPublicKey[:]),
	)
}

func GenerateFakeKeyPairFromDomainNameForTesting(adscertCallsign string) ([32]byte, [32]byte) {
	privateKey := sha256.Sum256([]byte(adscertCallsign))
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey, privateKey
}
