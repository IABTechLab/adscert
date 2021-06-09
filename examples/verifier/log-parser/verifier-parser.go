package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"os"
	"strings"

	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/benbjohnson/clock"
)

var (
	hostCallsign            = flag.String("host_callsign", "", "ads.cert callsign for the host party")
	originCallsign          = flag.String("origin_callsign", "", "ads.cert callsign for the originating party")
	useFakeKeyGeneratingDNS = flag.Bool("use_fake_key_generating_dns_for_testing", false,
		"When enabled, this code skips performing real DNS lookups and instead simulates DNS-based keys by generating a key pair based on the domain name.")
	signatureLogFile = flag.String("signature_log_file", "", "Verify all logged signatures and hashes in file")
)

func main() {
	flag.Parse()

	logger.Logger.Info("Verifying log file.")

	file, err := os.Open(*signatureLogFile)
	if err != nil {
		logger.Logger.Fatal("Failed to open file: %s", err)
	}
	defer file.Close()

	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*hostCallsign)

	signatory := adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*hostCallsign, privateKeysBase64, *useFakeKeyGeneratingDNS)
	// Force an update to the counter-party manager for known origin callsign before processing log
	signatory.SynchronizeForTesting(*originCallsign)
	signer := adscert.NewAuthenticatedConnectionsSigner(
		signatory,
		rand.Reader,
		clock.New(),
	)

	var logCount, parseErrorCount, verifyErrorCount, validRequestCount, validUrlCount int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		logCount++
		line := scanner.Text()
		signatureParams, err := parseLog(line)
		if err != nil {
			parseErrorCount++
			logger.Logger.Error("Error parsing log: %s", err)
			continue
		}

		// verification only returns an error if there are issues trying to validate the signatures
		// as opposed to whether the signatures are actually valid or not.
		verification, err := signer.VerifyAuthenticatedConnection(*signatureParams)
		if err != nil {
			verifyErrorCount++
			logger.Logger.Error("unable to verify message: %s", err)
			continue
		}

		if verification.BodyValid {
			validRequestCount++
		}
		if verification.URLValid {
			validUrlCount++
		}
		logger.Logger.Info("Valid Request Body: %t, Valid Request URL: %t", verification.BodyValid, verification.URLValid)
	}

	logger.Logger.Info("\n--- Summary --- \nlogEntries: %d, parseErrors: %d, verificationErrors: %d, validRequests: %d, validUrls: %d", logCount, parseErrorCount, verifyErrorCount, validRequestCount, validUrlCount)

	if err := scanner.Err(); err != nil {
		logger.Logger.Fatal("Error reading line: %s ", err)
	}
}

func parseLog(log string) (*adscert.AuthenticatedConnectionSignatureParams, error) {
	parsedLog := strings.Split(log, ",")

	var hashedRequestBody [32]byte
	var hashedDestinationURL [32]byte
	InvocationHostname := parsedLog[0]
	signaturesHeader := parsedLog[1]
	hashedRequestBodyBytes, err := base64.StdEncoding.DecodeString(parsedLog[2])
	if err != nil {
		logger.Logger.Error("Error decoding string: ", err)
		return nil, err
	}
	hashedDestinationURLBytes, err := base64.StdEncoding.DecodeString(parsedLog[3])
	if err != nil {
		return nil, err
	}
	copy(hashedRequestBody[:], hashedRequestBodyBytes[:32])
	copy(hashedDestinationURL[:], hashedDestinationURLBytes[:32])

	return &adscert.AuthenticatedConnectionSignatureParams{
		InvocationHostname:       InvocationHostname,
		HashedRequestBody:        &hashedRequestBody,
		HashedDestinationURL:     &hashedDestinationURL,
		SignatureMessageToVerify: []string{signaturesHeader},
	}, nil
}
