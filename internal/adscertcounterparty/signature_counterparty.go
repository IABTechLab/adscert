package adscertcounterparty

type signatureCounterparty struct {
	counterpartyInfo counterpartyInfo
}

func (c *signatureCounterparty) GetAdsCertIdentityDomain() string {
	return c.counterpartyInfo.registerableDomain
}

func (c *signatureCounterparty) GetStatus() CounterpartyStatus {
	return StatusUnspecified
}

func (c *signatureCounterparty) HasSharedSecret() bool {
	return c.counterpartyInfo.allSharedSecrets[c.counterpartyInfo.currentSharedSecret] != nil
}

func (c *signatureCounterparty) SharedSecret() SharedSecret {
	if !c.HasSharedSecret() {
		return nil
	}
	sharedSecret := c.counterpartyInfo.allSharedSecrets[c.counterpartyInfo.currentSharedSecret]
	return SharedSecret(sharedSecret)
}

func (c *signatureCounterparty) KeyID() string {
	return "a1b2c3"
}
