package keysecurity_test

import (
	"encoding/base64"
	"testing"

	"github.com/IABTechLab/adscert/pkg/adscert/keysecurity"
)

const (
	insecurePlaintextKeyURI = "insecure-plaintext-kms://"
)

func TestInsecurePlaintextClient_RoundTrip(t *testing.T) {
	kmsClient := keysecurity.NewInsecurePlaintextClient()
	sharedAEAD, err := kmsClient.GetAEAD(insecurePlaintextKeyURI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotCiphertext, err := sharedAEAD.Encrypt([]byte(examplePlaintext), []byte(exampleAdditionalData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	encodedExamplePlaintext := base64.RawURLEncoding.EncodeToString([]byte(examplePlaintext))
	if encodedExamplePlaintext != "RXhhbXBsZSBtZXNzYWdl" {
		t.Fatalf("Test message didn't encode to the expected value. (Did you change it?)")
	}
	gotEncodedCiphertext := base64.RawURLEncoding.EncodeToString(gotCiphertext)
	wantEncodedCiphertext := "UNENCRYPTED_SECRET_VALUE_HANDLE_WIITH_CARE__RXhhbXBsZSBtZXNzYWdl"
	if gotEncodedCiphertext != wantEncodedCiphertext {
		t.Errorf("Wrong ciphertext: got %q, want %q", gotEncodedCiphertext, wantEncodedCiphertext)
	}
	gotPlaintext, err := sharedAEAD.Decrypt(gotCiphertext, []byte(exampleAdditionalData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(gotPlaintext) != examplePlaintext {
		t.Errorf("wrong plaintext roundtrip: got %q, want %q", string(gotPlaintext), examplePlaintext)
	}
}

func TestInsecurePlaintextClient_IncorrectURI(t *testing.T) {
	kmsClient := keysecurity.NewInsecurePlaintextClient()
	_, err := kmsClient.GetAEAD("unknown-key-encryption://")
	if err == nil || err.Error() != "keyURI must be insecure-plaintext-kms://, but got unknown-key-encryption://" {
		t.Errorf("Expected error using wrong URI, but got %v", err)
	}
}
