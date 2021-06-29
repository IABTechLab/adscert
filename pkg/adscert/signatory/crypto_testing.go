package signatory

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
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

type keyGeneratingDNSResolver struct{}

func (r *keyGeneratingDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	adsCertRecord := GenerateFakeAdsCertRecordForTesting(name)
	logger.Infof("Serving fake DNS record for %s: %s", name, adsCertRecord)
	return []string{adsCertRecord}, nil
}

func NewFakeKeyGeneratingDnsResolver() discovery.DNSResolver {
	return &keyGeneratingDNSResolver{}
}
