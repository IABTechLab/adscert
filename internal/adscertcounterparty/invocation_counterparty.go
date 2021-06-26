package adscertcounterparty

type invocationCounterparty struct {
	counterpartyInfo          counterpartyInfo
	signatureCounterpartyInfo []counterpartyInfo
}

func (c *invocationCounterparty) GetStatus() CounterpartyStatus {
	return StatusUnspecified
}

func (c *invocationCounterparty) GetSignatureCounterparties() []SignatureCounterparty {
	result := []SignatureCounterparty{}

	for _, counterparty := range c.signatureCounterpartyInfo {
		result = append(result, &signatureCounterparty{counterpartyInfo: counterparty})
	}

	return result
}
