package discovery

import "fmt"

type DomainIndexer interface {
	LookupIdentitiesForDomain(domain string) ([]DomainInfo, error)
}

type CounterpartyStatus int

const (
	StatusUnspecified CounterpartyStatus = iota
	StatusOK
	StatusNotYetChecked
	StatusErrorOnDNS
	StatusErrorOnDNSSEC
	StatusErrorOnAdsCertConfigParse
	StatusErrorOnAdsCertConfigEval
	StatusErrorOnKeyValidation
	StatusErrorOnSharedSecretCalculation
)

func (cs CounterpartyStatus) String() string {
	// TODO: This was just a proof-of-concept for signature statuses. The design doc has a more
	// up-to-date representation of structured outcome codes.
	return fmt.Sprintf("%d", cs)
}
