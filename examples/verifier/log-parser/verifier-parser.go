package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"os"
	"strings"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
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

	logger.Infof("Verifying log file.")

	file, err := os.Open(*signatureLogFile)
	if err != nil {
		logger.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	privateKeysBase64 := signatory.GenerateFakePrivateKeysForTesting(*hostCallsign)

	signatory := signatory.NewLocalAuthenticatedConnectionsSignatory(*hostCallsign, rand.Reader, clock.New(), privateKeysBase64, *useFakeKeyGeneratingDNS)

	// Force an update to the counter-party manager for known origin callsign before processing log
	// signatory.SynchronizeForTesting(*originCallsign)

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
		verification, err := signatory.VerifyAuthenticatedConnection(signatureRequest)
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

	InvocationHostname := parsedLog[0]
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
		InvocationHostname: InvocationHostname,
	}

	copy(reqInfo.UrlHash[:], hashedDestinationURLBytes[:32])
	copy(reqInfo.BodyHash[:], hashedRequestBodyBytes[:32])

	return &api.AuthenticatedConnectionVerificationRequest{
		RequestInfo:      reqInfo,
		SignatureMessage: []string{signaturesHeader},
	}, nil
}
