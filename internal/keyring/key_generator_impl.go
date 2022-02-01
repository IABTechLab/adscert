package keyring

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// n.b. compile time check that keyGeneratorImpl implements KeyGenerator interface
var _ KeyGenerator = (*keyGeneratorImpl)(nil)

type keyGeneratorImpl struct {
}

func (k *keyGeneratorImpl) GenerateKeysForConfig(config *AdsCertKeyConfig) error {
	publicKeyBase64, privateKeyBytes, err := generateKeyPair()
	if err != nil {
		return err
	}
	config.PublicKeyBase64 = publicKeyBase64
	config.KeyID = publicKeyBase64[0:6]

	// Somehow we need to indicate which KMS is preferred

	clearKey(privateKeyBytes[:])
	return nil
}

func generateKeyPair() (string, *[32]byte, error) {
	privateBytes := &[32]byte{}
	if n, err := crypto_rand.Read(privateBytes[:]); err != nil {
		return "", nil, err
	} else if n != 32 {
		return "", nil, fmt.Errorf("wrong key size generated: %d != 32", n)
	}

	publicBytes := &[32]byte{}
	curve25519.ScalarBaseMult(publicBytes, privateBytes)

	return encodeKeyBase64(publicBytes[:]), privateBytes, nil
}

func encodeKeyBase64(keyBytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(keyBytes)
}

func clearKey(data []byte) {
	for i := range data {
		data[i] = 0x00
	}
}
