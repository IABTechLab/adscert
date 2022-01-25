/*
Copyright © 2022 IAB Technology Laboratory, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/curve25519"
)

// basicinsecurekeygenCmd represents the basicinsecurekeygen command
var basicinsecurekeygenCmd = &cobra.Command{
	Use:   "basicinsecurekeygen",
	Short: "A basic tool for generating insecure private key configurations for testing.",
	Long:  `Generates a base64-encoded private key and calculates the corresponding public key.`,
	Run: func(cmd *cobra.Command, args []string) {
		generateAndPrint()
	},
}

func init() {
	rootCmd.AddCommand(basicinsecurekeygenCmd)
}

func generateAndPrint() {
	publicKey, privateKey, err := generateKeyPair()
	if err != nil {
		fmt.Printf("Error: failed to generate key pair: %v", err)
	}
	fmt.Println("Randomly generated key pair")
	fmt.Printf("Public key:  %s\n", publicKey)
	fmt.Printf("Private key: %s\n", privateKey)
	fmt.Printf("DNS TXT Entry: \"v=adcrtd k=x25519 h=sha256 p=%s\"\n", publicKey)
}

func generateKeyPair() (string, string, error) {
	privateBytes := &[32]byte{}
	if n, err := crypto_rand.Read(privateBytes[:]); err != nil {
		return "", "", err
	} else if n != 32 {
		return "", "", fmt.Errorf("wrong key size generated: %d != 32", n)
	}

	publicBytes := &[32]byte{}
	curve25519.ScalarBaseMult(publicBytes, privateBytes)

	return encodeKeyBase64(publicBytes[:]), encodeKeyBase64(privateBytes[:]), nil
}

func encodeKeyBase64(keyBytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(keyBytes)
}
