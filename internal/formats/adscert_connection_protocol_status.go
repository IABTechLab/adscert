package formats

type AuthenticatedConnectionProtocolStatus int

const (
	StatusUnspecified AuthenticatedConnectionProtocolStatus = iota // this status is considered and handled as an error condition
	StatusOK
	StatusDeactivated
	StatusUnavailable
	StatusTesting
	StatusNotYetChecked
	StatusErrorOnSignature
	StatusErrorOnDNS
	StatusErrorOnDNSSEC
	StatusErrorOnAdsCertConfigParse
	StatusErrorOnAdsCertConfigEval
	StatusErrorOnKeyValidation
	StatusErrorOnSharedSecretCalculation
	StatusKeyFetchPending
	StatusReviewPending
	StatusDnsReturnedRCode
	StatusADPFParseError
	StatusADCRTDParseError
	StatusAdvisoryOnly
	StatusSuppressed
	StatusDelayed
)
