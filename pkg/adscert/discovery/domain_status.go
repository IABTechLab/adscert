package discovery

type DomainStatus int

const (
	DomainStatusUnspecified DomainStatus = iota // this status is considered and handled as an error condition
	DomainStatusOK
	DomainStatusUnavailable
	DomainStatusNotYetChecked
	DomainStatusKeyFetchPending
	DomainStatusErrorOnDNS
	DomainStatusErrorOnDNSSEC
	DomainStatusErrorOnSharedSecretCalculation
	DomainStatusADPFParseError
	DomainStatusADCRTDParseError
)
