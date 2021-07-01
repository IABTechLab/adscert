package signatory

import (
	"crypto/sha256"
	"fmt"
	"net/url"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/formats"
	"golang.org/x/net/publicsuffix"
)

func SetRequestInfo(requestInfo *api.RequestInfo, url string, body []byte) error {

	_, tldPlusOne, err := parseURLComponents(url)
	if err != nil {
		return fmt.Errorf("unable to parse domain from URL: %v", err)
	}
	requestInfo.InvokingDomain = tldPlusOne

	urlHash := sha256.Sum256([]byte(url))
	requestInfo.UrlHash = urlHash[:]

	bodyHash := sha256.Sum256(body)
	requestInfo.BodyHash = bodyHash[:]

	return err
}

func GetSignatures(response *api.AuthenticatedConnectionSignatureResponse) []string {
	signatures := make([]string, 0)

	for _, si := range response.SignatureInfo {
		signatures = append(signatures, si.SignatureMessage)
	}

	return signatures
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

// set from the diagnostic array printed by formats.AuthenticatedConnectionSignature
// this avoids having to manuallly set every property when returning a repsonse
func setSignatureInfoFromAuthenticatedConnection(sigInfo *api.SignatureInfo, acs *formats.AuthenticatedConnectionSignature) {
	diag := acs.GetAttributeArray()
	sigInfo.FromDomain = diag[0]
	sigInfo.FromKey = diag[1]
	sigInfo.InvokingDomain = diag[2]
	sigInfo.ToDomain = diag[3]
	sigInfo.ToKey = diag[4]
	sigInfo.SigningStatus = diag[7]
}
