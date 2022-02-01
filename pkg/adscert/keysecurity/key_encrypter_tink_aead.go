package keysecurity

import (
	"encoding/base64"
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
)

// n.b. compile time check that keyEncrypterTinkAead implements KeyEncrypter interface
var _ KeyEncrypter = (*keyEncrypterTinkAead)(nil)

type keyEncrypterTinkAead struct{}

func NewKeyEncrypterTinkAead() (KeyEncrypter, error) {
	return &keyEncrypterTinkAead{}, nil
}

func (k *keyEncrypterTinkAead) EncryptKeyToBase64Ciphertext(kmsURI string, data []byte, publicKeyBase64Encoded string) (string, error) {
	aead, err := getBackendForURI(kmsURI)
	if err != nil {
		return "", err
	}
	additionalAuthenticatedData, err := base64.RawURLEncoding.DecodeString(publicKeyBase64Encoded)
	if err != nil {
		return "", err
	}
	ciphertext, err := aead.Encrypt(data, additionalAuthenticatedData)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (k *keyEncrypterTinkAead) DecryptKeyFromBase64Ciphertext(kmsURI string, ciphertextBase64Encoded string, publicKeyBase64Encoded string) ([]byte, error) {
	aead, err := getBackendForURI(kmsURI)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextBase64Encoded)
	if err != nil {
		return nil, err
	}
	additionalAuthenticatedData, err := base64.RawURLEncoding.DecodeString(publicKeyBase64Encoded)
	if err != nil {
		return nil, err
	}
	return aead.Decrypt(ciphertext, additionalAuthenticatedData)
}

func getBackendForURI(kmsURI string) (tink.AEAD, error) {
	kmsClient, err := registry.GetKMSClient(kmsURI)
	if err != nil {
		return nil, err
	}
	backend, err := kmsClient.GetAEAD(kmsURI)
	if err != nil {
		return nil, fmt.Errorf("invalid aead backend: %v", err)
	}
	return backend, nil
}
