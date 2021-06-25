package main

import (
	"bufio"
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
)

var (
	method         = flag.String("http_method", "GET", "HTTP method, 'GET' or 'POST'")
	destinationURL = flag.String("url", "https://google.com/gen_204", "URL to invoke")
	body           = flag.String("body", "", "POST request body")
	sendRequests   = flag.Bool("send_requests", false, "Actually invoke the web server")
	frequency      = flag.Duration("frequency", 10*time.Second, "Frequency to invoke the specified URL")

	originCallsign = flag.String("origin_callsign", "", "ads.cert callsign for the originating party")

	signatureLogFile = flag.String("signature_log_file", "", "write signature and hashes to file for offline verification")

	useFakeKeyGeneratingDNS = flag.Bool("use_fake_key_generating_dns_for_testing", false,
		"When enabled, this code skips performing real DNS lookups and instead simulates DNS-based keys by generating a key pair based on the domain name.")
)

func main() {
	flag.Parse()

	logger.Infof("Starting demo client.")

	privateKeysBase64 := signatory.GenerateFakePrivateKeysForTesting(*originCallsign)

	var dnsResolver discovery.DNSResolver
	if *useFakeKeyGeneratingDNS {
		dnsResolver = discovery.NewFakeDnsResolver()
	} else {
		dnsResolver = discovery.NewRealDnsResolver()
	}

	var signatureFileLogger *log.Logger
	if *signatureLogFile != "" {
		file, err := os.OpenFile(*signatureLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logger.Fatalf(err.Error())
		}
		defer file.Close()

		signatureFileLogger = log.New(file, "" /*=prefix*/, 0 /*=flag=*/)
	}

	demoClient := DemoClient{
		Signatory: signatory.NewLocalAuthenticatedConnectionsSignatory(*originCallsign, crypto_rand.Reader, clock.New(), dnsResolver, privateKeysBase64),

		Method:         *method,
		DestinationURL: *destinationURL,
		Body:           []byte(*body),

		ActuallySendRequest: *sendRequests,
		Ticker:              time.NewTicker(*frequency),

		SignatureFileLogger: signatureFileLogger,
	}
	demoClient.StartRequestLoop()
}

type DemoClient struct {
	Signatory signatory.AuthenticatedConnectionsSignatory

	Method         string
	DestinationURL string
	Body           []byte

	ActuallySendRequest bool
	Ticker              *time.Ticker

	SignatureFileLogger *log.Logger
}

func (c *DemoClient) StartRequestLoop() {
	c.initiateRequest()
	for range c.Ticker.C {
		if err := c.initiateRequest(); err != nil {
			logger.Warningf("Error sending request: %v", err)
		}
	}
}

func (c *DemoClient) initiateRequest() error {

	req, err := http.NewRequest(c.Method, c.DestinationURL, bytes.NewReader(c.Body))
	if err != nil {
		return fmt.Errorf("error building HTTP request: %v", err)
	}

	reqInfo := &api.RequestInfo{}
	signatory.SetRequestInfo(reqInfo, *destinationURL, c.Body)

	signatureResponse, err := c.Signatory.SignAuthenticatedConnection(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
			Timestamp:   "",
			Nonce:       "",
		})
	if err != nil {
		logger.Warningf("unable to sign message (continuing...): %v", err)
	}

	req.Header["X-Ads-Cert-Auth"] = signatory.GetSignatures(signatureResponse)

	logger.Infof("Requesting URL %s %s with signature %s", req.Method, req.URL, signatureResponse)

	if c.SignatureFileLogger != nil {
		_, invocationHostname, err := utils.ParseURLComponents(c.DestinationURL)
		if err != nil {
			return fmt.Errorf("error parsing destination url: %s", err)
		}
		urlHash := sha256.Sum256([]byte(c.DestinationURL))
		bodyHash := sha256.Sum256([]byte(c.Body))

		c.SignatureFileLogger.Printf("%s,%s,%s,%s", invocationHostname, signatureResponse.SignatureInfo[0], base64.StdEncoding.EncodeToString(bodyHash[:]), base64.StdEncoding.EncodeToString(urlHash[:]))
	}

	if c.ActuallySendRequest {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("error sending HTTP request: %v", err)
		}

		scanner := bufio.NewScanner(resp.Body)
		for i := 0; scanner.Scan() && i < 5; i++ {
			logger.Infof("Received reply: %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading response: %v", err)
		}
	} else {
		logger.Infof("(Request not actually sent)")
	}
	return nil
}
