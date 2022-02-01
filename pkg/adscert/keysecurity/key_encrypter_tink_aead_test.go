package keysecurity_test

import (
	"encoding/base64"
	"testing"

	"github.com/IABTechLab/adscert/pkg/adscert/keysecurity"
	"github.com/google/tink/go/core/registry"
)

const (
	examplePublicKey = "Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA"
)

func TestKeyEncrypterTinkAead_RoundTrip(t *testing.T) {
	registry.RegisterKMSClient(keysecurity.NewInsecurePlaintextClient())
	keyEncrypter, err := keysecurity.NewKeyEncrypterTinkAead()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotCiphertext, err := keyEncrypter.EncryptKeyToBase64Ciphertext("insecure-plaintext-kms://", []byte(examplePlaintext), examplePublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	encodedExamplePlaintext := base64.RawURLEncoding.EncodeToString([]byte(examplePlaintext))
	if encodedExamplePlaintext != "RXhhbXBsZSBtZXNzYWdl" {
		t.Fatalf("Test message didn't encode to the expected value. (Did you change it?)")
	}
	wantCiphertext := "UNENCRYPTED_SECRET_VALUE_HANDLE_WIITH_CARE__RXhhbXBsZSBtZXNzYWdl"

	if gotCiphertext != wantCiphertext {
		t.Fatalf("ciphertext mismatch: got %q, want %q", gotCiphertext, wantCiphertext)
	}
}
