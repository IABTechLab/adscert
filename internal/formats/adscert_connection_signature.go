package formats

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	attributeFrom             = "from"
	attributeFromKey          = "from_key"
	attributeInvoking         = "invoking"
	attributeTo               = "to"
	attributeToKey            = "to_key"
	attributeTimestamp        = "timestamp"
	attributeNonce            = "nonce"
	attributeStatus           = "status"
	attributeSignatureForBody = "sigb"
	attributeSignatureForURL  = "sigu"
	hmacLength                = 12
)

var (
	ErrParamMissingFrom      = errors.New("parameter missing: from")
	ErrParamMissingFromKey   = errors.New("parameter missing: fromKey")
	ErrParamMissingInvoking  = errors.New("parameter missing: invoking")
	ErrParamMissingTo        = errors.New("parameter missing: to")
	ErrParamMissingToKey     = errors.New("parameter missing: toKey")
	ErrParamMissingTimestamp = errors.New("parameter missing: timestamp")
	ErrParamMissingNonce     = errors.New("parameter missing: nonce")
	ErrParamMissingStatus    = errors.New("parameter missing: status")

	ErrACSWrongNumParams = errors.New("wrong authenticated connection num params")
)

type AuthenticatedConnectionSignature struct {
	from             string
	fromKey          string
	invoking         string
	to               string
	toKey            string
	timestamp        string
	nonce            string
	status           string
	signatureForBody string
	signatureForURL  string
}

func (s *AuthenticatedConnectionSignature) GetAttributeInvoking() string {
	return s.invoking
}

func (s *AuthenticatedConnectionSignature) GetAttributeFrom() string {
	return s.from
}

func (s *AuthenticatedConnectionSignature) EncodeMessage() string {
	values := url.Values{}
	conditionallyAdd(&values, attributeFrom, s.from)
	conditionallyAdd(&values, attributeFromKey, s.fromKey)
	conditionallyAdd(&values, attributeInvoking, s.invoking)
	conditionallyAdd(&values, attributeTo, s.to)
	conditionallyAdd(&values, attributeToKey, s.toKey)
	conditionallyAdd(&values, attributeTimestamp, s.timestamp)
	conditionallyAdd(&values, attributeNonce, s.nonce)
	conditionallyAdd(&values, attributeStatus, s.status)
	return values.Encode()
}

func (s *AuthenticatedConnectionSignature) AddParametersForSignature(
	fromKey string, to string, toKey string, timestamp string, nonce string) error {
	if fromKey == "" {
		return ErrParamMissingFromKey
	}
	if to == "" {
		return ErrParamMissingTo
	}
	if toKey == "" {
		return ErrParamMissingToKey
	}
	if timestamp == "" {
		return ErrParamMissingTimestamp
	}
	if nonce == "" {
		return ErrParamMissingNonce
	}

	s.fromKey = fromKey
	s.to = to
	s.toKey = toKey
	s.timestamp = timestamp
	s.nonce = nonce

	return nil
}

func (s *AuthenticatedConnectionSignature) CompareSignatures(signatureForBody []byte, signatureForURL []byte) (bool, bool) {
	bodyMatch := hmac.Equal([]byte(B64truncate(signatureForBody, hmacLength)), []byte(s.signatureForBody))
	urlMatch := hmac.Equal([]byte(B64truncate(signatureForURL, hmacLength)), []byte(s.signatureForURL))
	return bodyMatch, urlMatch
}

func EncodeSignatureSuffix(
	signatureForBody []byte, signatureForURL []byte) string {
	values := url.Values{}
	conditionallyAdd(&values, attributeSignatureForBody, B64truncate(signatureForBody, hmacLength))
	conditionallyAdd(&values, attributeSignatureForURL, B64truncate(signatureForURL, hmacLength))
	return "; " + values.Encode()
}

func NewAuthenticatedConnectionSignature(status string, from string, invoking string) (*AuthenticatedConnectionSignature, error) {
	if status == "" {
		return nil, ErrParamMissingStatus
	}
	if from == "" {
		return nil, ErrParamMissingFrom
	}
	if invoking == "" {
		return nil, ErrParamMissingInvoking
	}

	s := &AuthenticatedConnectionSignature{}

	s.status = status
	s.from = from
	s.invoking = invoking

	return s, nil
}

func DecodeAuthenticatedConnectionSignature(encodedMessage string) (*AuthenticatedConnectionSignature, error) {
	splitSignature := strings.Split(encodedMessage, ";")
	if len(splitSignature) != 2 {
		return nil, ErrACSWrongNumParams
	}

	message := strings.TrimSpace(splitSignature[0])
	sigs := strings.TrimSpace(splitSignature[1])

	values, err := url.ParseQuery(message)
	if err != nil {
		return nil, fmt.Errorf("query string parse failure: %v", err)
	}

	parsedSigs, err := url.ParseQuery(sigs)
	if err != nil {
		return nil, fmt.Errorf("signature string parse failure: %v", err)
	}

	s := &AuthenticatedConnectionSignature{}

	s.from = getFirstMapElement(values[attributeFrom])
	s.fromKey = getFirstMapElement(values[attributeFromKey])
	s.invoking = getFirstMapElement(values[attributeInvoking])
	s.to = getFirstMapElement(values[attributeTo])
	s.toKey = getFirstMapElement(values[attributeToKey])
	s.timestamp = getFirstMapElement(values[attributeTimestamp])
	s.nonce = getFirstMapElement(values[attributeNonce])
	s.status = getFirstMapElement(values[attributeStatus])

	s.signatureForBody = getFirstMapElement(parsedSigs[attributeSignatureForBody])
	s.signatureForURL = getFirstMapElement(parsedSigs[attributeSignatureForURL])
	return s, nil
}
