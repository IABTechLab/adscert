package adscertcounterparty

type signatureCounterparty struct {
	counterpartyInfo counterpartyInfo
}

func (c *signatureCounterparty) GetAdsCertIdentityDomain() string {
	return c.counterpartyInfo.domain
}

func (c *signatureCounterparty) GetStatus() CounterpartyStatus {
	return StatusUnspecified
}

func (c *signatureCounterparty) HasSharedSecret() bool {
	return c.counterpartyInfo.allSharedSecrets[c.counterpartyInfo.currentSharedSecretId] != nil
}

func (c *signatureCounterparty) SharedSecret() SharedSecret {
	if !c.HasSharedSecret() {
		return nil
	}
	sharedSecret := c.counterpartyInfo.allSharedSecrets[c.counterpartyInfo.currentSharedSecretId]
	return SharedSecret(sharedSecret)
}
