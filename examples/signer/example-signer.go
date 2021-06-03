package main

import (
	"bufio"
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/golang/glog"
)

var (
	method         = flag.String("http_method", "GET", "HTTP method, 'GET' or 'POST'")
	destinationURL = flag.String("url", "https://google.com/gen_204", "URL to invoke")
	body           = flag.String("body", "", "POST request body")
	sendRequests   = flag.Bool("send_requests", false, "Actually invoke the web server")
	frequency      = flag.Duration("frequency", 10*time.Second, "Frequency to invoke the specified URL")

	originCallsign = flag.String("origin_callsign", "", "ads.cert callsign for the originating party")

	logFile = flag.String("log_file", "", "write signature and hashes to file for offline verification")

	useFakeKeyGeneratingDNS = flag.Bool("use_fake_key_generating_dns_for_testing", false,
		"When enabled, this code skips performing real DNS lookups and instead simulates DNS-based keys by generating a key pair based on the domain name.")
)

func main() {
	flag.Parse()

	glog.Info("Starting demo client.")

	privateKeysBase64 := adscertcrypto.GenerateFakePrivateKeysForTesting(*originCallsign)

	var fileLogger *log.Logger
	if *logFile != "" {
		file, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			glog.Fatal(err)
		}
		defer file.Close()

		fileLogger = log.New(file, "", 0)
		log.SetOutput(file)
	}

	demoClient := DemoClient{
		Signer: adscert.NewAuthenticatedConnectionsSigner(
			adscertcrypto.NewLocalAuthenticatedConnectionsSignatory(*originCallsign, privateKeysBase64, *useFakeKeyGeneratingDNS), crypto_rand.Reader),

		Method:         *method,
		DestinationURL: *destinationURL,
		Body:           []byte(*body),

		ActuallySendRequest: *sendRequests,
		Ticker:              time.NewTicker(*frequency),

		FileLogger: fileLogger,
	}
	demoClient.StartRequestLoop()
}

type DemoClient struct {
	Signer adscert.AuthenticatedConnectionsSigner

	Method         string
	DestinationURL string
	Body           []byte

	ActuallySendRequest bool
	Ticker              *time.Ticker

	FileLogger *log.Logger
}

func (c *DemoClient) StartRequestLoop() {
	c.initiateRequest()
	for range c.Ticker.C {
		if err := c.initiateRequest(); err != nil {
			glog.Warningf("Error sending request: %v", err)
		}
	}
}

func (c *DemoClient) initiateRequest() error {
	req, err := http.NewRequest(c.Method, c.DestinationURL, bytes.NewReader(c.Body))
	if err != nil {
		return fmt.Errorf("error building HTTP request: %v", err)
	}

	signature, err := c.Signer.SignAuthenticatedConnection(
		adscert.AuthenticatedConnectionSignatureParams{
			DestinationURL: c.DestinationURL,
			RequestBody:    c.Body,
		})
	if err != nil {
		glog.Warningf("unable to sign message (continuing...): %v", err)
	}

	req.Header["X-Ads-Cert-Auth"] = signature.SignatureMessages

	glog.Infof("Requesting URL %s %s with headers %v", req.Method, req.URL, req.Header)

	if *logFile != "" {
		urlHash := sha256.Sum256([]byte(c.DestinationURL))
		bodyHash := sha256.Sum256([]byte(c.Body))

		c.FileLogger.Printf("%s,%s,%s", urlHash, bodyHash, signature.SignatureMessages)
	}

	if c.ActuallySendRequest {
		glog.Info("Sending request...")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("error sending HTTP request: %v", err)
		}

		scanner := bufio.NewScanner(resp.Body)
		for i := 0; scanner.Scan() && i < 5; i++ {
			fmt.Println(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading response: %v", err)
		}
	} else {
		glog.Info("(Request not actually sent)")
	}
	return nil
}
