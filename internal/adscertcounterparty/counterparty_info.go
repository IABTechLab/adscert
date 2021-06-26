package adscertcounterparty

import (
	"time"
)

type counterpartyInfo struct {
	registerableDomain  string
	currentPublicKey    keyAlias
	currentSharedSecret keyTupleAlias
	lastUpdateTime      time.Time

	allPublicKeys    keyMap
	allSharedSecrets keyTupleMap

	signatureCounterpartyDomains []string
}
