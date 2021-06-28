package main

import (
	"bufio"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"flag"
	"os"
	"strings"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
)

var (
	hostCallsign     = flag.String("host_callsign", "", "ads.cert callsign for the host party")
	originCallsign   = flag.String("origin_callsign", "", "ads.cert callsign for the originating party")
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

	privateKeysBase64 := signatory.GenerateFakePrivateKeysForTesting(*hostCallsign)

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		*hostCallsign,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		privateKeysBase64)

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

		if verification.BodyValid {
			validRequestCount++
		}
		if verification.UrlValid {
			validUrlCount++
		}
		logger.Infof("Valid Request Body: %t, Valid Request URL: %t", verification.BodyValid, verification.UrlValid)
	}

	logger.Infof("\n--- Summary --- \nlogEntries: %d, parseErrors: %d, verificationErrors: %d, validRequests: %d, validUrls: %d", logCount, parseErrorCount, verifyErrorCount, validRequestCount, validUrlCount)

	if err := scanner.Err(); err != nil {
		logger.Fatalf("Error reading line: %s ", err)
	}
}

func parseLog(log string) (*api.AuthenticatedConnectionVerificationRequest, error) {
	parsedLog := strings.Split(log, ",")

	invokingDomain := parsedLog[0]
	signaturesHeader := parsedLog[1]
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
	}

	copy(reqInfo.UrlHash[:], hashedDestinationURLBytes[:32])
	copy(reqInfo.BodyHash[:], hashedRequestBodyBytes[:32])

	return &api.AuthenticatedConnectionVerificationRequest{
		RequestInfo:      reqInfo,
		SignatureMessage: []string{signaturesHeader},
	}, nil
}
