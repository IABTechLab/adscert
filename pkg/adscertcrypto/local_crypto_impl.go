package adscertcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/IABTechLab/adscert/internal/adscertcounterparty"
	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/internal/metrics"
)

type AuthenticatedConnectionsSignatory interface {
	EmbossSigningPackage(request *api.AuthenticatedConnectionSigningPackage) (*api.AuthenticatedConnectionSignatureResponse, error)
	VerifySigningPackage(request *api.AuthenticatedConnectionVerificationPackage) (*api.AuthenticatedConnectionVerificationResponse, error)

	// TODO: Design a better way to do this testing hook.
	SynchronizeForTesting(invocationTLDPlusOne string)
}

func NewLocalAuthenticatedConnectionsSignatory(originCallsign string, privateKeyBase64Strings []string, useFakeKeyGeneratingDNS bool) AuthenticatedConnectionsSignatory {
	var dnsResolver adscertcounterparty.DNSResolver
	if useFakeKeyGeneratingDNS {
		dnsResolver = NewFakeKeyGeneratingDnsResolver()
	} else {
		dnsResolver = adscertcounterparty.NewRealDnsResolver()
	}
	return &localAuthenticatedConnectionsSignatory{
		counterpartyManager: adscertcounterparty.NewCounterpartyManager(dnsResolver, privateKeyBase64Strings),
		originCallsign:      originCallsign,
	}
}

type localAuthenticatedConnectionsSignatory struct {
	originCallsign string

	counterpartyManager adscertcounterparty.CounterpartyAPI
}

func (s *localAuthenticatedConnectionsSignatory) SynchronizeForTesting(invocationTLDPlusOne string) {
	s.counterpartyManager.LookUpInvocationCounterpartyByHostname(invocationTLDPlusOne)
	s.counterpartyManager.SynchronizeForTesting()
}

func (s *localAuthenticatedConnectionsSignatory) EmbossSigningPackage(request *api.AuthenticatedConnectionSigningPackage) (*api.AuthenticatedConnectionSignatureResponse, error) {
	// Note: this is basically going to be the same process for signing and verifying except the lookup method.
	response := &api.AuthenticatedConnectionSignatureResponse{}

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

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *api.AuthenticatedConnectionSigningPackage, counterparty adscertcounterparty.SignatureCounterparty) (*api.SignatureInfo, error) {
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

func (s *localAuthenticatedConnectionsSignatory) VerifySigningPackage(request *api.AuthenticatedConnectionVerificationPackage) (*api.AuthenticatedConnectionVerificationResponse, error) {
	response := &api.AuthenticatedConnectionVerificationResponse{}

	acs, err := formats.DecodeAuthenticatedConnectionSignature(request.SignatureMessage)
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
