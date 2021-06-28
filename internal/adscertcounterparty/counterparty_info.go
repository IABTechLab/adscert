package adscertcounterparty

import (
	"time"
)

type counterpartyInfo struct {
	domain                string
	currentPublicKeyId    keyAlias
	currentSharedSecretId keyPairAlias
	lastUpdateTime        time.Time

	allPublicKeys    keyMap
	allSharedSecrets keyPairMap

	signatureCounterpartyDomains []string
}
