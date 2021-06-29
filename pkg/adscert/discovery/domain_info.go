package discovery

import (
	"time"

	"github.com/IABTechLab/adscert/internal/formats"
)

type DomainInfo struct {
	Domain                string   // root domain for this record, can be invoking or identity domain
	IdentityDomains       []string // used to map from invoking domain to parent identity domains
	currentPublicKeyId    keyAlias
	currentSharedSecretId keyPairAlias
	allPublicKeys         keyMap
	allSharedSecrets      keyPairMap

	protocolStatus formats.AuthenticatedConnectionProtocolStatus
	lastUpdateTime time.Time
}

type SharedSecret interface {
	LocalKeyID() string
	RemoteKeyID() string
	Secret() *[32]byte
}

func (c *DomainInfo) GetAdsCertIdentityDomain() string {
	return c.Domain
}

func (c *DomainInfo) GetStatus() formats.AuthenticatedConnectionProtocolStatus {
	return c.protocolStatus
}

func (c *DomainInfo) GetSharedSecret() (SharedSecret, bool) {
	sharedSecret, ok := c.allSharedSecrets[c.currentSharedSecretId]
	return sharedSecret, ok
}
