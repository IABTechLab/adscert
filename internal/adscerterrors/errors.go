package adscerterrors

import (
	"errors"

	"github.com/IABTechLab/adscert/internal/errorcode"
)

type DiscoveryErrorCode *errorcode.Error

var (
	ErrDNSLookup             DiscoveryErrorCode = errorcode.New("dns_lookup", errors.New("failed to lookup DNS"))
	ErrDNSDecodePolicy       DiscoveryErrorCode = errorcode.New("dns_decode_policy", errors.New("failed to decode dns record policy"))
	ErrDNSDecodeKeys         DiscoveryErrorCode = errorcode.New("dns_decode_key", errors.New("failed to decode dns record keys"))
	ErrDiscoverySharedSecret DiscoveryErrorCode = errorcode.New("discovery_create_shared_secret", errors.New("failed to create shared secret"))
)

type SigningErrorCode *errorcode.Error

var (
	ErrSigningGenerateNonce      SigningErrorCode = errorcode.New("generate_nonce", errors.New("failed to generate nonce"))
	ErrSigningCounterpartyLookup SigningErrorCode = errorcode.New("invocation_counterparty_lookup", errors.New("failed to lookup invocation counterparty"))
	ErrSigningEmbossMessage      SigningErrorCode = errorcode.New("emboss_message", errors.New("failed to emboss message"))
)

type VerifyErrorCode *errorcode.Error

var (
	ErrVerifyDecodeSignature              VerifyErrorCode = errorcode.New("decode_signature", errors.New("failed to decode signature"))
	ErrVerifySignatureRequestHostMismatch VerifyErrorCode = errorcode.New("signature_host_mismatch", errors.New("invocation hostname does not match request"))
	ErrVerifyCounterpartyLookup           VerifyErrorCode = errorcode.New("counterparty_lookup", errors.New("failed to lookup signature counterparty"))
	ErrVerifyMissingSharedSecret          VerifyErrorCode = errorcode.New("missing_shared_secret", errors.New("signature counterparty missing shared secret"))
	ErrVerifyInvalidSignature             VerifyErrorCode = errorcode.New("invalid_signature", errors.New("signature is not valid"))
)
