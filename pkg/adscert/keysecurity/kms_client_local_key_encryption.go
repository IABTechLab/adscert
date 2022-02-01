package keysecurity

import (
	"fmt"
	"io"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

const localKeyEncryptionPrefix = "local-key-encryption://"

// n.b. compile time check that localKeyEncryptionClient implements registry.KMSClient interface
var _ registry.KMSClient = (*localKeyEncryptionClient)(nil)

type localKeyEncryptionClient struct {
	sharedAEAD tink.AEAD
}

// NewLocalKeyEncryptionClient returns a KMS client which will handle encryption
// locally using the supplied, shared Tink keyring.  It is up to the implementer
// to ensure that the supplied keyring is being handled securely.
// keyURI must have the following format: 'local-key-encryption://'.
func NewLocalKeyEncryptionClient(jsonCleartextKeyEncryptionKeysetReader io.Reader) (registry.KMSClient, error) {
	sharedAEAD, err := createAEAD(jsonCleartextKeyEncryptionKeysetReader)
	if err != nil {
		return nil, err
	}
	return &localKeyEncryptionClient{
		sharedAEAD: sharedAEAD,
	}, nil
}

// Supported returns true if this client does support keyURI.
func (c *localKeyEncryptionClient) Supported(keyURI string) bool {
	return keyURI == localKeyEncryptionPrefix
}

// GetAEAD returns an AEAD by keyURI.
func (c *localKeyEncryptionClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, fmt.Errorf("keyURI must be %s, but got %s", localKeyEncryptionPrefix, keyURI)
	}
	return c.sharedAEAD, nil
}

// createAEAD creates a shared AEAD instance from the provided json-encoded
// Tink keyset.
func createAEAD(jsonCleartextKeyEncryptionKeysetReader io.Reader) (tink.AEAD, error) {
	ksr := keyset.NewJSONReader(jsonCleartextKeyEncryptionKeysetReader)
	ks, err := ksr.Read()
	if err != nil {
		return nil, err
	}

	handle, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		return nil, err
	}

	return aead.New(handle)
}
