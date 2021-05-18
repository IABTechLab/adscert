package adscertcrypto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/IABTechLab/adscert/internal/adscertcounterparty"
	"github.com/golang/glog"
	"golang.org/x/crypto/curve25519"
)

func GenerateFakePrivateKeysForTesting(adscertCallsign string) []string {
	_, primaryPrivateKey := GenerateFakeKeyPairFromDomainNameForTesting("_delivery._adscert." + adscertCallsign)
	_, alternatePrivateKey := GenerateFakeKeyPairFromDomainNameForTesting("alternate._delivery._adscert." + adscertCallsign)
	return []string{
		base64.RawURLEncoding.EncodeToString(primaryPrivateKey[:]),
		base64.RawURLEncoding.EncodeToString(alternatePrivateKey[:])}
}

func GenerateFakeAdsCertRecordForTesting(adscertCallsign string) string {
	primaryPublicKey, _ := GenerateFakeKeyPairFromDomainNameForTesting(adscertCallsign)
	alternatePublicKey, _ := GenerateFakeKeyPairFromDomainNameForTesting("alternate." + adscertCallsign)

	return fmt.Sprintf("v=adcrtd k=x25519 h=sha256 p=%s p=%s",
		base64.RawURLEncoding.EncodeToString(primaryPublicKey[:]),
		base64.RawURLEncoding.EncodeToString(alternatePublicKey[:]))
}

func GenerateFakeKeyPairFromDomainNameForTesting(adscertCallsign string) ([32]byte, [32]byte) {
	privateKey := sha256.Sum256([]byte(adscertCallsign))
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey, privateKey
}

type keyGeneratingDNSResolver struct{}

func (r *keyGeneratingDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	adsCertRecord := GenerateFakeAdsCertRecordForTesting(name)
	glog.Infof("Serving fake DNS record for %s: %s", name, adsCertRecord)
	return []string{adsCertRecord}, nil
}

func NewFakeKeyGeneratingDnsResolver() adscertcounterparty.DNSResolver {
	return &keyGeneratingDNSResolver{}
}
