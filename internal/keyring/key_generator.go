package keyring

type KeyGenerator interface {
	GenerateKeysForConfig(config *AdsCertKeyConfig) error
}
