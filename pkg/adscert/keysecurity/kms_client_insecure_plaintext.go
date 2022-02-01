package keysecurity

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
)

const insecurePlaintextPrefix = "insecure-plaintext-kms://"

// Base64 encodes to "UNENCRYPTED_SECRET_VALUE_HANDLE_WIITH_CARE__"
var fakeEncryptionPreface = []byte("\x50\xd1\x0d\x09\x16\x0f\x4c\x40\xff\x48\x40\x91\x11\x3f\xd5\x00\xb5\x04\xfc\x70\x0d\x0c\xb1\x3f\x58\x82\x13\x1f\xf0\x80\x44\x4f\xff")

// n.b. compile time check that insecurePlaintextClient implements registry.KMSClient interface
var _ registry.KMSClient = (*insecurePlaintextClient)(nil)

type insecurePlaintextClient struct{}

// NewClient returns a fake KMS client which will handle keys with uriPrefix prefix.
// keyURI must have the following format: 'insecure-plaintext-kms://'.
func NewInsecurePlaintextClient() registry.KMSClient {
	return &insecurePlaintextClient{}
}

// Supported returns true if this client does support keyURI.
func (c *insecurePlaintextClient) Supported(keyURI string) bool {
	return keyURI == insecurePlaintextPrefix
}

// GetAEAD returns an AEAD by keyURI.
func (c *insecurePlaintextClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, fmt.Errorf("keyURI must be %s, but got %s", insecurePlaintextPrefix, keyURI)
	}
	return &insecurePlaintextAEAD{}, nil
}

type insecurePlaintextAEAD struct{}

// Encrypt encrypts plaintext with additionalData as additional
// authenticated data. The resulting ciphertext allows for checking
// authenticity and integrity of additional data additionalData,
// but there are no guarantees wrt. secrecy of that data.
func (k *insecurePlaintextAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	ciphertext := make([]byte, len(fakeEncryptionPreface)+len(plaintext))
	copy(ciphertext, fakeEncryptionPreface)
	copy(ciphertext[len(fakeEncryptionPreface):], plaintext)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with {@code additionalData} as additional
// authenticated data. The decryption verifies the authenticity and integrity
// of the additional data, but there are no guarantees wrt. secrecy of that data.
func (k *insecurePlaintextAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext)-len(fakeEncryptionPreface))
	copy(plaintext, ciphertext[len(fakeEncryptionPreface):])
	return plaintext, nil
}
