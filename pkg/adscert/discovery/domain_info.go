package discovery

import (
	"time"
)

type DomainInfo struct {
	Domain                string   // root domain for this record, can be invoking or identity domain
	IdentityDomains       []string // used to map from invoking domain to parent identity domains
	currentPublicKeyId    keyAlias
	currentSharedSecretId keyPairAlias
	allPublicKeys         keyMap
	allSharedSecrets      keyPairMap
	lastUpdateTime        time.Time
}

type SharedSecret interface {
	LocalKeyID() string
	RemoteKeyID() string
	Secret() *[32]byte
}

func (c *DomainInfo) GetAdsCertIdentityDomain() string {
	return c.Domain
}

func (c *DomainInfo) GetStatus() CounterpartyStatus {
	return StatusUnspecified
}

func (c *DomainInfo) HasSharedSecret() bool {
	return c.allSharedSecrets[c.currentSharedSecretId] != nil
}

func (c *DomainInfo) SharedSecret() SharedSecret {
	if !c.HasSharedSecret() {
		return nil
	}
	sharedSecret := c.allSharedSecrets[c.currentSharedSecretId]
	return SharedSecret(sharedSecret)
}
