package signatory

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/IABTechLab/adscert/internal/adscertcounterparty"
	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/internal/metrics"
	"github.com/benbjohnson/clock"
)

func NewLocalAuthenticatedConnectionsSignatory(originCallsign string, reader io.Reader, clock clock.Clock, privateKeyBase64Strings []string, useFakeKeyGeneratingDNS bool) AuthenticatedConnectionsSignatory {

	var dnsResolver adscertcounterparty.DNSResolver
	if useFakeKeyGeneratingDNS {
		dnsResolver = NewFakeKeyGeneratingDnsResolver()
	} else {
		dnsResolver = adscertcounterparty.NewRealDnsResolver()
	}

	return &localAuthenticatedConnectionsSignatory{
		originCallsign:      originCallsign,
		secureRandom:        reader,
		clock:               clock,
		counterpartyManager: adscertcounterparty.NewCounterpartyManager(dnsResolver, privateKeyBase64Strings),
	}
}

type localAuthenticatedConnectionsSignatory struct {
	originCallsign string
	secureRandom   io.Reader
	clock          clock.Clock

	counterpartyManager adscertcounterparty.CounterpartyAPI
}

func (s *localAuthenticatedConnectionsSignatory) SynchronizeForTesting(invocationTLDPlusOne string) {
	s.counterpartyManager.LookUpInvocationCounterpartyByHostname(invocationTLDPlusOne)
	s.counterpartyManager.SynchronizeForTesting()
}

func (s *localAuthenticatedConnectionsSignatory) SignAuthenticatedConnection(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error) {

	// Note: this is basically going to be the same process for signing and verifying except the lookup method.
	var err error
	response := &api.AuthenticatedConnectionSignatureResponse{}

	// generate timestamp
	if request.Timestamp == "" {
		request.Timestamp = s.clock.Now().UTC().Format("060102T150405")
	}

	// generate nonce
	if request.Nonce == "" {
		request.Nonce, err = s.generateNonce()
		if err != nil {
			metrics.RecordSigningMetrics(metrics.SignErrorGenerateNonce)
		}
	}

	// TODO: psl cleanup
	invocationCounterparty, err := s.counterpartyManager.LookUpInvocationCounterpartyByHostname(request.RequestInfo.InvocationHostname)
	if err != nil {
		return nil, err
	}

	for _, counterparty := range invocationCounterparty.GetSignatureCounterparties() {
		signatureInfo, err := s.embossSingleMessage(request, counterparty)
		if err != nil {
			return nil, err
		}
		response.SignatureInfo = append(response.SignatureInfo, signatureInfo)
	}

	return response, nil
}

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *api.AuthenticatedConnectionSignatureRequest, counterparty adscertcounterparty.SignatureCounterparty) (*api.SignatureInfo, error) {
	acs, err := formats.NewAuthenticatedConnectionSignature(counterparty.GetStatus().String(), s.originCallsign, request.RequestInfo.InvocationHostname)
	if err != nil {
		return nil, fmt.Errorf("error constructing authenticated connection signature format: %v", err)
	}

	signatureInfo := &api.SignatureInfo{
		FromDomain:     s.originCallsign,
		InvokingDomain: request.RequestInfo.InvocationHostname,
	}

	if !counterparty.HasSharedSecret() {
		signatureInfo.SignatureMessage = acs.EncodeMessage()
		return signatureInfo, nil
	}

	sharedSecret := counterparty.SharedSecret()

	if err = acs.AddParametersForSignature(sharedSecret.LocalKeyID(),
		counterparty.GetAdsCertIdentityDomain(),
		sharedSecret.RemoteKeyID(),
		request.Timestamp,
		request.Nonce); err != nil {
		// TODO: Figure out how we want to expose structured metadata for failed signing ops.
		return nil, fmt.Errorf("error adding signature params: %v", err)
	}

	// TODO: SignatureInfo needs to include the signature operation status.
	signatureInfo.FromKey = sharedSecret.LocalKeyID()
	signatureInfo.ToDomain = counterparty.GetAdsCertIdentityDomain()
	signatureInfo.ToKey = sharedSecret.RemoteKeyID()

	message := acs.EncodeMessage()
	bodyHMAC, urlHMAC := generateSignatures(counterparty, []byte(message), request.RequestInfo.BodyHash[:], request.RequestInfo.UrlHash[:])
	signatureInfo.SignatureMessage = message + formats.EncodeSignatureSuffix(bodyHMAC, urlHMAC)
	return signatureInfo, nil
}

func (s *localAuthenticatedConnectionsSignatory) VerifyAuthenticatedConnection(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {
	response := &api.AuthenticatedConnectionVerificationResponse{}

	// TODO: change this so that the verification request can pass multiple signature messages.
	// Let the signatory pick through the multiple messages (if present) and figure out what
	// to do with them.
	signatureMessage := request.SignatureMessage[0]
	acs, err := formats.DecodeAuthenticatedConnectionSignature(signatureMessage)
	if err != nil {
		metrics.RecordVerifyMetrics(metrics.VerifyErrorSignatureDecode)
		return response, fmt.Errorf("signature decode failure: %v", err)
	}

	// Validate invocation hostname matches request
	if acs.GetAttributeInvoking() != request.RequestInfo.InvocationHostname {
		// TODO: Unrelated signature error
		logger.Infof("unrelated signature %s versus %s", acs.GetAttributeInvoking(), request.RequestInfo.InvocationHostname)
		metrics.RecordVerifyMetrics(metrics.VerifyErrorUnrelatedSignature)
		return response, fmt.Errorf("unrelated signature %s versus %s", acs.GetAttributeInvoking(), request.RequestInfo.InvocationHostname)
	}

	// Look up originator by callsign
	signatureCounterparty, err := s.counterpartyManager.LookUpSignatureCounterpartyByCallsign(acs.GetAttributeFrom())
	if err != nil {
		logger.Infof("counterparty lookup error")
		metrics.RecordVerifyMetrics(metrics.VerifyErrorCounterPartyLookUp)
		return response, err
	}

	if !signatureCounterparty.HasSharedSecret() {
		// TODO: shared secret missing error
		logger.Infof("no shared secret")
		metrics.RecordVerifyMetrics(metrics.VerifyErrorNoSharedSecret)
		return response, nil
	}

	bodyHMAC, urlHMAC := generateSignatures(signatureCounterparty, []byte(acs.EncodeMessage()), request.RequestInfo.BodyHash[:], request.RequestInfo.UrlHash[:])
	response.BodyValid, response.UrlValid = acs.CompareSignatures(bodyHMAC, urlHMAC)
	return response, nil
}

func generateSignatures(counterparty adscertcounterparty.SignatureCounterparty, message []byte, bodyHash []byte, urlHash []byte) ([]byte, []byte) {
	h := hmac.New(sha256.New, counterparty.SharedSecret().Secret()[:])

	h.Write([]byte(message))
	h.Write(bodyHash)
	bodyHMAC := h.Sum(nil)

	h.Write(urlHash)
	urlHMAC := h.Sum(nil)

	return bodyHMAC, urlHMAC
}

func (s *localAuthenticatedConnectionsSignatory) generateNonce() (string, error) {
	var nonce [32]byte
	n, err := io.ReadFull(s.secureRandom, nonce[:])
	if err != nil {
		return "", fmt.Errorf("error generating random: %v", err)
	}
	if n != 32 {
		return "", fmt.Errorf("unexpected number of random values: %d", n)
	}
	return formats.B64truncate(nonce[:], 12), nil
}
