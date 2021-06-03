package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Curtis notes:
// This code is really only meant to assist with the proof-of-concept.  Please see the design doc
// for details about the proper key generation and storage solution that will replace this code.

func main() {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: failed to generate key pair: %v", err)
	}
	fmt.Println("Randomly generated key pair")
	fmt.Printf("Public key:  %s\n", publicKey)
	fmt.Printf("Private key: %s\n", privateKey)
	fmt.Printf("DNS TXT Entry: \"v=adcrtd k=x25519 h=sha256 p=%s\"\n", publicKey)
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

	return EncodeKeyBase64(publicBytes[:]), EncodeKeyBase64(privateBytes[:]), nil
}

func EncodeKeyBase64(keyBytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(keyBytes)
}
