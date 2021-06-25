package signatory

import (
	"crypto/sha256"
	"fmt"
	"net/url"

	"github.com/IABTechLab/adscert/internal/api"
	"golang.org/x/net/publicsuffix"
)

func SetRequestInfo(requestInfo *api.RequestInfo, url string, body []byte) error {

	_, tldPlusOne, err := parseURLComponents(url)
	if err != nil {
		// TODO: switch to using a named error message indicating URL parse failure.
		return fmt.Errorf("unable to parse domain from URL: %v", err)
	}
	requestInfo.InvokingDomain = tldPlusOne

	urlHash := sha256.Sum256([]byte(url))
	copy(requestInfo.UrlHash[:], urlHash[:])

	bodyHash := sha256.Sum256(body)
	copy(requestInfo.BodyHash[:], bodyHash[:])

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
