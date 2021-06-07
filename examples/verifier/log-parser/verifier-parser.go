package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"os"
	"strings"

	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/golang/glog"
)

var (
	hostCallsign            = flag.String("host_callsign", "", "ads.cert callsign for the originating party")
	useFakeKeyGeneratingDNS = flag.Bool("use_fake_key_generating_dns_for_testing", false,
		"When enabled, this code skips performing real DNS lookups and instead simulates DNS-based keys by generating a key pair based on the domain name.")
	signatureLogFile = flag.String("signature_log_file", "", "Verify all logged signatures and hashes in file")
)

func main() {
	flag.Parse()

	glog.Info("Verifying log file.")

	file, err := os.Open(*signatureLogFile)
	if err != nil {
		glog.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*hostCallsign)
	signer := adscert.NewAuthenticatedConnectionsSigner(
		adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*hostCallsign, privateKeysBase64, *useFakeKeyGeneratingDNS),
	)

	var logCount, parseErrorCount, verifyErrorCount, validRequestCount, validUrlCount int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		logCount++
		line := scanner.Text()
		verificationPackage, err := parseLog(line)
		if err != nil {
			parseErrorCount++
			glog.Errorf("Error parsing log: ", err)
			continue
		}

		verification, err := signer.VerifyAuthenticatedConnectionWithPackage(*verificationPackage)
		if err != nil {
			verifyErrorCount++
			glog.Errorf("unable to verify message: ", err)
			continue
		}

		if verification.BodyValid {
			validRequestCount++
		}
		if verification.URLValid {
			validUrlCount++
		}
		glog.Infof("Valid Request Body: %t, Valid Request URL: %t", verification.BodyValid, verification.URLValid)
	}

	glog.Infof("\n--- Summary --- \nlogEntries: %d, parseErrors: %d, verificationErrors: %d, validRequests: %d, validUrls: %d", logCount, parseErrorCount, verifyErrorCount, validRequestCount, validUrlCount)

	if err := scanner.Err(); err != nil {
		glog.Fatal("Error reading line: %s ", err)
	}
}

func parseLog(log string) (*adscertcrypto.AuthenticatedConnectionVerificationPackage, error) {
	parsedLog := strings.Split(log, ",")

	var hashedRequestBody [32]byte
	var hashedDestinationURL [32]byte
	invocationHostname := parsedLog[0]
	signaturesHeader := parsedLog[1]
	hashedRequestBodyBytes, err := base64.StdEncoding.DecodeString(parsedLog[2])
	if err != nil {
		return nil, err
	}
	hashedDestinationURLBytes, err := base64.StdEncoding.DecodeString(parsedLog[3])
	if err != nil {
		return nil, err
	}
	copy(hashedRequestBody[:], hashedRequestBodyBytes[:32])
	copy(hashedDestinationURL[:], hashedDestinationURLBytes[:32])

	return &adscertcrypto.AuthenticatedConnectionVerificationPackage{
		RequestInfo: adscertcrypto.RequestInfo{
			InvocationHostname: invocationHostname,
			URLHash:            hashedDestinationURL,
			BodyHash:           hashedRequestBody,
		},
		SignatureMessage: string(signaturesHeader),
	}, nil
}
