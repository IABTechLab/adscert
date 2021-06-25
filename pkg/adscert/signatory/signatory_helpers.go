package signatory

import (
	"crypto/sha256"
	"fmt"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/utils"
)

func SetRequestInfo(requestInfo *api.RequestInfo, url string, body []byte) error {

	parsedURL, tldPlusOne, err := utils.ParseURLComponents(url)
	if err != nil {
		// TODO: switch to using a named error message indicating URL parse failure.
		return fmt.Errorf("unable to parse destination URL: %v", err)
	}
	requestInfo.InvokingDomain = tldPlusOne

	urlHash := sha256.Sum256([]byte(parsedURL.String()))
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
