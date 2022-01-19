package signatory

import (
	"crypto/sha256"
	"fmt"
	"net/url"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
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

func SetRequestSignatures(requestInfo *api.RequestInfo, signatures []string) {
	for _, v := range signatures {
		requestInfo.SignatureInfo = append(requestInfo.SignatureInfo, &api.SignatureInfo{SignatureMessage: v})
	}
}

func GetSignatures(response *api.AuthenticatedConnectionSignatureResponse) []string {
	signatures := make([]string, 0)

	for _, si := range response.RequestInfo.SignatureInfo {
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

// helper function to set message and fields from the diagnostic array printed by formats.AuthenticatedConnectionSignature
// this avoids having to manuallly set every field when returning a response
func setSignatureInfoFromAuthenticatedConnection(sigInfo *api.SignatureInfo, acs *formats.AuthenticatedConnectionSignature) {
	sigInfo.FromDomain = acs.GetAttributeFrom()
	sigInfo.FromKey = acs.GetAttributeFromKey()
	sigInfo.InvokingDomain = acs.GetAttributeInvoking()
	sigInfo.ToDomain = acs.GetAttributeTo()
	sigInfo.ToKey = acs.GetAttributeToKey()
	sigInfo.SigningStatus = acs.GetAttributeStatusAsString()
	sigInfo.SignatureMessage = acs.EncodeMessage()
}
