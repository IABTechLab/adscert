package adscerterrors

import (
	"errors"

	"github.com/IABTechLab/adscert/internal/errorcode"
)

type DNSLookupErrorCode *errorcode.Error

var (
	ErrDNSLookup       DNSLookupErrorCode = errorcode.New("dns_lookup", errors.New("failed to lookup DNS"))
	ErrDNSDecodePolicy DNSLookupErrorCode = errorcode.New("dns_decode_policy", errors.New("failed to decode dns record policy"))
	ErrDNSDecodeKeys   DNSLookupErrorCode = errorcode.New("dns_decode_key", errors.New("failed to decode dns record keys"))
)

type SigningErrorCode *errorcode.Error

var (
	ErrSigningGenerateNonce                SigningErrorCode = errorcode.New("generate_nonce", errors.New("failed to generate nonce"))
	ErrSigningInvocationCounterpartyLookup SigningErrorCode = errorcode.New("invocation_counterparty_lookup", errors.New("failed to lookup invocation counterparty"))
	ErrSigningEmbossMessage                SigningErrorCode = errorcode.New("emboss_message", errors.New("failed to emboss message"))
)

type VerifyErrorCode *errorcode.Error

var (
	ErrVerifyDecodeSignature              VerifyErrorCode = errorcode.New("decode_signature", errors.New("failed to decode signature"))
	ErrVerifySignatureRequestHostMismatch VerifyErrorCode = errorcode.New("signature_host_mismatch", errors.New("invocation hostname does not match request"))
	ErrVerifyCounterpartyLookup           VerifyErrorCode = errorcode.New("counterparty_lookup", errors.New("failed to lookup signature counterparty"))
	ErrVerifyMissingSharedSecret          VerifyErrorCode = errorcode.New("missing_shared_secret", errors.New("signature counterparty missing shared secret"))
)
