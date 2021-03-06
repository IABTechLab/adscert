package discovery

import (
	"fmt"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"golang.org/x/crypto/curve25519"
)

// x25519Key provides a lightweight, typed wrapper around computed
// shared secret material to permit pass-by-value.
type x25519Key struct {
	keyBytes  [32]byte
	alias     keyAlias
	pairAlias keyPairAlias
}

func (x *x25519Key) Secret() *[32]byte {
	return &x.keyBytes
}

func (x *x25519Key) LocalKeyID() string {
	return string(x.pairAlias.originKeyAlias)
}

func (x *x25519Key) RemoteKeyID() string {
	return string(x.pairAlias.remoteKeyAlias)
}

type keyAlias string

type keyPairAlias struct {
	originKeyAlias keyAlias
	remoteKeyAlias keyAlias
}

func newKeyPairAlias(originKeyId keyAlias, remoteKeyId keyAlias) keyPairAlias {
	return keyPairAlias{originKeyAlias: originKeyId, remoteKeyAlias: remoteKeyId}
}

type keyMap map[keyAlias]*x25519Key

type keyPairMap map[keyPairAlias]*x25519Key

func asKeyMap(adsCertKeys formats.AdsCertKeys) keyMap {
	result := keyMap{}

	for _, k := range adsCertKeys.PublicKeys {
		x25519Key := &x25519Key{
			alias: keyAlias(k.KeyAlias),
		}
		if n := copy(x25519Key.keyBytes[:], k.PublicKeyBytes); n != 32 {
			logger.Warningf("wrong number of bytes copied for key alias %s: %d != 32", k.KeyAlias, n)
			continue
		}
		result[x25519Key.alias] = x25519Key
	}

	return result
}

// Calculate shared secret between two parties (using a origin party's private key and remote party's public key).
// This key will be used to sign and verify connections between these parties.
func calculateSharedSecret(originPrivateKey *x25519Key, remotePublicKey *x25519Key) (*x25519Key, error) {
	secret, err := curve25519.X25519(originPrivateKey.keyBytes[:], remotePublicKey.keyBytes[:])
	if err != nil {
		return nil, err
	}

	result := &x25519Key{
		pairAlias: newKeyPairAlias(originPrivateKey.alias, remotePublicKey.alias),
	}
	copy(result.keyBytes[:], secret)

	return result, err
}

func privateKeysToKeyMap(privateKeys []string) (keyMap, error) {
	result := keyMap{}

	for _, privateKeyBase64 := range privateKeys {
		privateKey, err := parseKeyFromString(privateKeyBase64)
		if err != nil {
			return nil, err
		}

		publicBytes := &[32]byte{}
		curve25519.ScalarBaseMult(publicBytes, &privateKey.keyBytes)

		keyAlias := keyAlias(formats.ExtractKeyAliasFromPublicKeyBase64(formats.EncodeKeyBase64(publicBytes[:])))
		privateKey.alias = keyAlias
		result[keyAlias] = privateKey
	}

	return result, nil
}

func parseKeyFromString(base64EncodedKey string) (*x25519Key, error) {
	var key x25519Key
	rawKeyBytes, err := formats.ParseBase64EncodedKey(base64EncodedKey, 32)
	if err != nil {
		return nil, err
	}
	if n := copy(key.keyBytes[:], rawKeyBytes); n != 32 {
		return nil, fmt.Errorf("wrong number of bytes copied: %d != 32", n)
	}
	return &key, nil
}
