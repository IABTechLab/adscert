package main

import (
	"bufio"
	"bytes"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
)

var (
	origin           = flag.String("origin", "", "ads.cert identity domain for the originating (sending) party")
	method           = flag.String("http_method", "GET", "HTTP method, 'GET' or 'POST'")
	destinationURL   = flag.String("url", "https://google.com/gen_204", "URL to invoke")
	body             = flag.String("body", "", "POST request body")
	sendRequests     = flag.Bool("send_requests", false, "Actually invoke the web server")
	frequency        = flag.Duration("frequency", 10*time.Second, "Frequency to invoke the specified URL")
	signatureLogFile = flag.String("signature_log_file", "", "write signature and hashes to file for offline verification")
)

func main() {
	flag.Parse()

	logger.Infof("Starting demo client.")

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(*origin)

	var signatureFileLogger *log.Logger
	if *signatureLogFile != "" {
		file, err := os.OpenFile(*signatureLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logger.Fatalf(err.Error())
		}
		defer file.Close()

		signatureFileLogger = log.New(file, "" /*=prefix*/, 0 /*=flag=*/)
	}

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		*origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(30*time.Second), // domain check interval
		time.Duration(30*time.Second), // domain renewal interval
		base64PrivateKeys)

	demoClient := DemoClient{
		Signatory: signatoryApi,

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
	err = signatory.SetRequestInfo(reqInfo, c.DestinationURL, c.Body)
	if err != nil {
		return fmt.Errorf("error parsing request info: %v", err)
	}

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
		c.SignatureFileLogger.Printf("%s,%s,%s,%s",
			reqInfo.BodyHash,
			signatureResponse.SignatureInfo[0],
			base64.StdEncoding.EncodeToString(reqInfo.BodyHash),
			base64.StdEncoding.EncodeToString(reqInfo.UrlHash))
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
