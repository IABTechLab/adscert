package formats

import "errors"

var (
	ErrEmptyInput               = errors.New("empty input")
	ErrVersionPrefixOutOfOrder  = errors.New("version prefix out of order")
	ErrVersionUnknown           = errors.New("unknown version string")
	ErrVersionMissing           = errors.New("missing version string or too many")
	ErrKeyAlgorithmWrongNumber  = errors.New("key algorithm missing or too many")
	ErrHashAlgorithmWrongNumber = errors.New("hash algorithm missing or too many")
	ErrPublicKeysMissing        = errors.New("public keys missing")
	ErrWrongKeySize             = errors.New("wrong key size")
	ErrZeroValueKey             = errors.New("zero-value key")
	ErrEmptyKey                 = errors.New("empty value for key")
	ErrUnsupportedAlgorithm     = errors.New("unsupported key algorithm")
	ErrBase64DecodeFailure      = errors.New("base64 decode failure")
	ErrPublicSuffixParseFailure = errors.New("public suffix parse failure")
	ErrNotTLDPlusOneDomain      = errors.New("not a TLD plus one domain")
)
