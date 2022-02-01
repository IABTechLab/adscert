package keysecurity_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/IABTechLab/adscert/pkg/adscert/keysecurity"
)

const (
	localKeyEncryptionURI = "local-key-encryption://"

	examplePlaintext      = "Example message"
	exampleAdditionalData = "Example additional data"

	messageEncryptedWithKeyID1438031939 = "AVW2oENljrJ96uEDzOJv-embipfA9gHYXFmPtnpgIGbWfPJoHwHhqHbaAls29Er8"

	malformedJSONKeyset = "}"

	exampleCleartextKeysetWithoutRotation = `
	{
		"key" : [
		   {
			  "status" : "ENABLED",
			  "outputPrefixType" : "TINK",
			  "keyId" : 19903171,
			  "keyData" : {
				 "value" : "GiBgfA0871XMQTVlPX9GGWlKigadsLr+mEVGnfxaTZZ3Ig==",
				 "typeUrl" : "type.googleapis.com/google.crypto.tink.AesGcmKey",
				 "keyMaterialType" : "SYMMETRIC"
			  }
		   }
		],
		"primaryKeyId" : 19903171
	 }
	`
	exampleCleartextKeysetWithKeyID1438031939 = `
	{
		"key" : [
		   {
			  "status" : "ENABLED",
			  "outputPrefixType" : "TINK",
			  "keyId" : 19903171,
			  "keyData" : {
				 "value" : "GiBgfA0871XMQTVlPX9GGWlKigadsLr+mEVGnfxaTZZ3Ig==",
				 "typeUrl" : "type.googleapis.com/google.crypto.tink.AesGcmKey",
				 "keyMaterialType" : "SYMMETRIC"
			  }
		   },
		   {
			  "keyId" : 1438031939,
			  "keyData" : {
				 "typeUrl" : "type.googleapis.com/google.crypto.tink.AesGcmKey",
				 "keyMaterialType" : "SYMMETRIC",
				 "value" : "GiAamlsR6jBUgRFdZU6bokW0rL4aA+ZSYhC8J0nTXb0gWQ=="
			  },
			  "outputPrefixType" : "TINK",
			  "status" : "ENABLED"
		   }
		],
		"primaryKeyId" : 1438031939
	 }
	`
)

func TestLocalKeyEncryptionClient_RoundTrip(t *testing.T) {
	kmsClient, err := keysecurity.NewLocalKeyEncryptionClient(strings.NewReader(exampleCleartextKeysetWithKeyID1438031939))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sharedAEAD, err := kmsClient.GetAEAD(localKeyEncryptionURI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotCiphertext, err := sharedAEAD.Encrypt([]byte(examplePlaintext), []byte(exampleAdditionalData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotPlaintext, err := sharedAEAD.Decrypt(gotCiphertext, []byte(exampleAdditionalData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(gotPlaintext) != examplePlaintext {
		t.Errorf("wrong plaintext roundtrip: got %q, want %q", string(gotPlaintext), examplePlaintext)
	}
}

func TestLocalKeyEncryptionClient_DecryptingWithCorrectKeyset(t *testing.T) {
	kmsClient, err := keysecurity.NewLocalKeyEncryptionClient(strings.NewReader(exampleCleartextKeysetWithKeyID1438031939))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sharedAEAD, err := kmsClient.GetAEAD(localKeyEncryptionURI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(messageEncryptedWithKeyID1438031939)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotPlaintext, err := sharedAEAD.Decrypt(ciphertext, []byte(exampleAdditionalData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(gotPlaintext) != examplePlaintext {
		t.Errorf("wrong plaintext roundtrip: got %q, want %q", string(gotPlaintext), examplePlaintext)
	}

}

func TestLocalKeyEncryptionClient_DecryptingWithWrongKeysetReturnsError(t *testing.T) {
	kmsClient, err := keysecurity.NewLocalKeyEncryptionClient(strings.NewReader(exampleCleartextKeysetWithoutRotation))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sharedAEAD, err := kmsClient.GetAEAD(localKeyEncryptionURI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(messageEncryptedWithKeyID1438031939)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = sharedAEAD.Decrypt(ciphertext, []byte(exampleAdditionalData))
	if err == nil || err.Error() != "aead_factory: decryption failed" {
		t.Errorf("Expected error decrypting message with wrong keyset, but got %v", err)
	}
}

func TestLocalKeyEncryptionClient_IncorrectURI(t *testing.T) {
	kmsClient, err := keysecurity.NewLocalKeyEncryptionClient(strings.NewReader(exampleCleartextKeysetWithoutRotation))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = kmsClient.GetAEAD("unknown-key-encryption://")
	if err == nil || err.Error() != "keyURI must be local-key-encryption://, but got unknown-key-encryption://" {
		t.Errorf("Expected error using wrong URI, but got %v", err)
	}
}

func TestLocalKeyEncryptionClient_MalformedKeyset(t *testing.T) {
	_, err := keysecurity.NewLocalKeyEncryptionClient(strings.NewReader(malformedJSONKeyset))
	if err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("Expected JSON decoding error messasge, but got %v", err)
	}
}
