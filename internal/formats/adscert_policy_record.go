package formats

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type AdsCertPolicy struct {
	CanonicalCallsignDomain string
}

func DecodeAdsCertPolicyRecord(input string) (*AdsCertPolicy, error) {
	// v=adpf a=adscorp.com
	parsedAdsCertPolicy := &AdsCertPolicy{}
	var versionOK int
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, ErrEmptyInput
	}

	tokens := strings.Split(input, " ")
	for i, token := range tokens {
		pair := strings.SplitN(token, "=", 2)
		if len(pair) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(pair[0]))
		value := strings.TrimSpace(pair[1])

		switch key {
		case "v":
			if i != 0 {
				// Per ads.cert specification, version must be specified first.
				return nil, ErrVersionPrefixOutOfOrder
			}
			if value != "adpf" {
				return nil, ErrVersionUnknown
			}
			versionOK++
		case "a":
			// alias as ads.cert callsign
			tldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(value)
			if err != nil {
				return nil, fmt.Errorf("callsign domain parse error: %v %w", err, ErrPublicSuffixParseFailure)
			}
			if tldPlusOne != value {
				return nil, fmt.Errorf("callsign error: %s %w", value, ErrNotTLDPlusOneDomain)
			}
			parsedAdsCertPolicy.CanonicalCallsignDomain = value
		}
	}
	if versionOK != 1 {
		return nil, ErrVersionMissing
	}
	return parsedAdsCertPolicy, nil
}
