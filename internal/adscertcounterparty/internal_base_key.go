package adscertcounterparty

import (
	"crypto/rand"
	"fmt"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"golang.org/x/crypto/curve25519"
)

// Curtis notes:
// The key management code is currently a mess, as there are different formats used by different
// low-level APIs, and I largely just used whatever was convenient at the time.  We should figure
// out what is the right way to work with this data.  There are some security considerations for
// this such as whether we have copies of key material scattered around in the application's memory.
// I'm hoping to get security engineer feedback on this.

// x25519Key provides a lightweight, typed wrapper around computed
// shared secret material to permit pass-by-value.
type x25519Key struct {
	keyBytes   [32]byte
	alias      keyAlias
	tupleAlias keyTupleAlias
}

func (x *x25519Key) Secret() *[32]byte {
	return &x.keyBytes
}

func (x *x25519Key) LocalKeyID() string {
	return string(x.tupleAlias.myKeyAlias)
}

func (x *x25519Key) RemoteKeyID() string {
	return string(x.tupleAlias.theirKeyAlias)
}

type keyAlias string

type keyTupleAlias struct {
	myKeyAlias    keyAlias
	theirKeyAlias keyAlias
}

func newKeyTupleAlias(myKeyID keyAlias, theirKeyID keyAlias) keyTupleAlias {
	return keyTupleAlias{myKeyAlias: myKeyID, theirKeyAlias: theirKeyID}
}

type keyMap map[keyAlias]*x25519Key

type keyTupleMap map[keyTupleAlias]*x25519Key

func asKeyMap(adsCertKeys formats.AdsCertKeys) keyMap {
	result := keyMap{}

	for _, k := range adsCertKeys.PublicKeys {
		x25519Key := &x25519Key{
			alias: keyAlias(k.KeyAlias),
		}
		if n := copy(x25519Key.keyBytes[:], k.PublicKeyBytes); n != 32 {
			logger.Logger.Warning("wrong number of bytes copied for key alias %s: %d != 32", k.KeyAlias, n)
			continue
		}
		result[x25519Key.alias] = x25519Key
	}

	return result
}

func calculateSharedSecret(myPrivate *x25519Key, theirPublic *x25519Key) (*x25519Key, error) {
	secret, err := curve25519.X25519(myPrivate.keyBytes[:], theirPublic.keyBytes[:])
	if err != nil {
		logger.Logger.Error("Error calculating shared secret: ", err)
		return nil, err
	}

	result := &x25519Key{
		tupleAlias: newKeyTupleAlias(myPrivate.alias, theirPublic.alias),
	}
	copy(result.keyBytes[:], secret)

	return result, err
}

func GenerateKeyPair() (string, string, error) {
	privateBytes := &[32]byte{}
	if n, err := rand.Read(privateBytes[:]); err != nil {
		return "", "", err
	} else if n != 32 {
		return "", "", fmt.Errorf("wrong key size generated: %d != 32", n)
	}

	publicBytes := &[32]byte{}
	curve25519.ScalarBaseMult(publicBytes, privateBytes)

	return formats.EncodeKeyBase64(publicBytes[:]), formats.EncodeKeyBase64(privateBytes[:]), nil
}

type keyReceiver interface {
	receivingSlice() []byte
	setKeyAlias(alias string)
	getKeyAlias() string
}

func privateKeysToKeyMap(privateKeys []string) (keyMap, error) {
	result := keyMap{}

	for _, privateKeyBase64 := range privateKeys {
		privateKey, err := parseKeyFromString(privateKeyBase64)
		if err != nil {
			logger.Logger.Error("Error parsing key: ", err)
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
		logger.Logger.Error("Error parsing encoded key: ", err)
		return nil, err
	}
	if n := copy(key.keyBytes[:], rawKeyBytes); n != 32 {
		return nil, fmt.Errorf("wrong number of bytes copied: %d != 32", n)
	}
	return &key, nil
}
