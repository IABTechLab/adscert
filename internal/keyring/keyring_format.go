package keyring

type AdsCertCallSignConfigList struct {
	Domains []*AdsCertCallSignConfig `json:"domains"`
}

type AdsCertCallSignConfig struct {
	Domain string          `json:"domain"`
	Realms []*AdsCertRealm `json:"realms"`
}

type AdsCertRealm struct {
	Realm string              `json:"realm"`
	Keys  []*AdsCertKeyConfig `json:"keys"`
}

type AdsCertKeyConfig struct {
	KeyID                string `json:"key_id"`
	PublicKeyBase64      string `json:"public_key"`
	EncryptedPrivateKey  string `json:"encrypted_private_key"`
	Status               string `json:"status"`
	TimestampCreated     string `json:"timestamp_created"`
	TimestampActivated   string `json:"timestamp_activated"`
	TimestampPrimaried   string `json:"timestamp_primaried"`
	TimestampSecondaried string `json:"timestamp_secondaried"`
	TimestampArchived    string `json:"timestamp_archived"`
	KeyEncryptionKeyURI  string `json:"key_encryption_key_uri"`
}

func (p *AdsCertCallSignConfigList) GetCallSignRealm(adscertCallSign string, realm string) *AdsCertRealm {
	return p.getCallSignConfig(adscertCallSign).getRealm(realm)
}

func (p *AdsCertCallSignConfigList) GetAllCallSignRealms() []*AdsCertRealm {
	var result []*AdsCertRealm
	for _, c := range p.Domains {
		result = append(result, c.Realms...)
	}
	return result
}

func (p *AdsCertCallSignConfigList) getCallSignConfig(adscertCallSign string) *AdsCertCallSignConfig {
	for _, c := range p.Domains {
		if c.Domain == adscertCallSign {
			return c
		}
	}
	c := &AdsCertCallSignConfig{
		Domain: adscertCallSign,
	}
	p.Domains = append(p.Domains, c)
	return c
}

func (p *AdsCertCallSignConfig) getRealm(realm string) *AdsCertRealm {
	for _, c := range p.Realms {
		if c.Realm == realm {
			return c
		}
	}
	c := &AdsCertRealm{
		Realm: realm,
	}
	p.Realms = append(p.Realms, c)
	return c
}
