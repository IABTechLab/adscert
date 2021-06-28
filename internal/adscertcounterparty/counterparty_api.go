package adscertcounterparty

import "fmt"

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

type CounterpartyAPI interface {
	LookUpInvocationCounterpartyByHostname(invocationHostname string) (InvocationCounterparty, error)
	LookUpSignatureCounterpartyByCallsign(adsCertCallsign string) (SignatureCounterparty, error)
	SynchronizeForTesting()
}

type InvocationCounterparty interface {
	GetStatus() CounterpartyStatus
	GetSignatureCounterparties() []SignatureCounterparty
}

type SignatureCounterparty interface {
	GetAdsCertIdentityDomain() string
	HasSharedSecret() bool
	SharedSecret() SharedSecret
	GetStatus() CounterpartyStatus
}

type SharedSecret interface {
	LocalKeyID() string
	RemoteKeyID() string
	Secret() *[32]byte
}

func (cs CounterpartyStatus) String() string {
	// TODO: This was just a proof-of-concept for signature statuses. The design doc has a more
	// up-to-date representation of structured outcome codes.
	return fmt.Sprintf("%d", cs)
}
