package keysecurity

type KeyEncrypter interface {
	EncryptKeyToBase64Ciphertext(kmsURI string, data []byte, publicKeyBase64Encoded string) (string, error)
	DecryptKeyFromBase64Ciphertext(kmsURI string, ciphertext string, publicKeyBase64Encoded string) ([]byte, error)
}
