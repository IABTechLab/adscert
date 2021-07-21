package main

import (
	"bufio"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
)

var (
	origin           = flag.String("origin", "", "ads.cert identity domain for the receiving party")
	signatureLogFile = flag.String("signature_log_file", "", "Verify all logged signatures and hashes in file")
)

func main() {
	flag.Parse()

	logger.Infof("Verifying log file.")

	file, err := os.Open(*signatureLogFile)
	if err != nil {
		logger.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(*origin)

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		*origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(30*time.Second), // domain check interval
		time.Duration(30*time.Second), // domain renewal interval
		base64PrivateKeys)

	var logCount, parseErrorCount, verifyErrorCount, validRequestCount, validUrlCount int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		logCount++
		line := scanner.Text()
		signatureRequest, err := parseLog(line)
		if err != nil {
			parseErrorCount++
			logger.Errorf("Error parsing log: %s", err)
			continue
		}

		// verification only returns an error if there are issues trying to validate the signatures
		// as opposed to whether the signatures are actually valid or not.
		verification, err := signatoryApi.VerifyAuthenticatedConnection(signatureRequest)
		if err != nil {
			verifyErrorCount++
			logger.Errorf("unable to verify message: %s", err)
			continue
		}

		if verification.VerificationInfo.BodyValid {
			validRequestCount++
		}
		if verification.VerificationInfo.UrlValid {
			validUrlCount++
		}
		logger.Infof("Valid Request Body: %t, Valid Request URL: %t", verification.VerificationInfo.BodyValid, verification.VerificationInfo.UrlValid)
	}

	logger.Infof("\n--- Summary --- \nlogEntries: %d, parseErrors: %d, verificationErrors: %d, validRequests: %d, validUrls: %d", logCount, parseErrorCount, verifyErrorCount, validRequestCount, validUrlCount)

	if err := scanner.Err(); err != nil {
		logger.Fatalf("Error reading line: %s ", err)
	}
}

func parseLog(log string) (*api.AuthenticatedConnectionVerificationRequest, error) {
	parsedLog := strings.Split(log, ",")

	invokingDomain := parsedLog[0]
	signatureHeader := parsedLog[1]
	hashedRequestBodyBytes, err := base64.StdEncoding.DecodeString(parsedLog[2])
	if err != nil {
		return nil, err
	}
	hashedDestinationURLBytes, err := base64.StdEncoding.DecodeString(parsedLog[3])
	if err != nil {
		return nil, err
	}

	reqInfo := &api.RequestInfo{
		InvokingDomain: invokingDomain,
		UrlHash:        hashedDestinationURLBytes[:32],
		BodyHash:       hashedRequestBodyBytes[:32],
	}
	signatory.SetRequestSignatures(reqInfo, []string{signatureHeader})

	return &api.AuthenticatedConnectionVerificationRequest{RequestInfo: reqInfo}, nil
}
