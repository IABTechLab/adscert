package signatory

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/IABTechLab/adscert/internal/api"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/benbjohnson/clock"
)

func NewLocalAuthenticatedConnectionsSignatory(originCallsign string, reader io.Reader, clock clock.Clock, dnsResolver discovery.DNSResolver, domainStore discovery.DomainStore, privateKeyBase64Strings []string) AuthenticatedConnectionsSignatory {
	return &localAuthenticatedConnectionsSignatory{
		originCallsign:      originCallsign,
		secureRandom:        reader,
		clock:               clock,
		counterpartyManager: discovery.NewDefaultDomainIndexer(dnsResolver, domainStore, privateKeyBase64Strings),
	}
}

type localAuthenticatedConnectionsSignatory struct {
	originCallsign string
	secureRandom   io.Reader
	clock          clock.Clock

	counterpartyManager discovery.DomainIndexer
}

func (s *localAuthenticatedConnectionsSignatory) SignAuthenticatedConnection(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error) {

	var err error
	startTime := time.Now()
	response := &api.AuthenticatedConnectionSignatureResponse{}

	if request.RequestInfo == nil || request.RequestInfo.InvokingDomain == "" || len(request.RequestInfo.UrlHash) == 0 {
		response.SignatureStatus = api.SignatureStatus_SIGNATURE_STATUS_MISSING_REQUIRED_PARAMETER
		return response, errors.New("required parameters are missing")
	}

	// add nonce and timestamp if not already provided in the request
	// this is the typical case to keep the client's usage simple
	if request.Timestamp == "" {
		request.Timestamp = s.clock.Now().UTC().Format("060102T150405")
	}
	if request.Nonce == "" {
		if request.Nonce, err = s.generateNonce(); err != nil {
			metrics.RecordSigning(adscerterrors.ErrSigningGenerateNonce)
		}
	}

	domainInfos, err := s.counterpartyManager.LookupIdentitiesForDomain(request.RequestInfo.InvokingDomain)
	if err != nil {
		metrics.RecordSigning(adscerterrors.ErrSigningInvocationCounterpartyLookup)
		response.SignatureStatus = api.SignatureStatus_SIGNATURE_STATUS_SIGNATORY_INTERNAL_ERROR
		return response, err
	}

	for _, domainInfo := range domainInfos {
		signatureInfo, err := s.embossSingleMessage(request, domainInfo)
		if err != nil {
			metrics.RecordSigning(adscerterrors.ErrSigningEmbossMessage)
			response.SignatureStatus = api.SignatureStatus_SIGNATURE_STATUS_SIGNATORY_INTERNAL_ERROR
			return response, err
		}
		response.SignatureInfo = append(response.SignatureInfo, signatureInfo)
	}

	metrics.RecordSigning(nil)
	metrics.RecordSigningTime(time.Since(startTime))
	response.SignatureStatus = api.SignatureStatus_SIGNATURE_STATUS_OK
	return response, nil
}

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *api.AuthenticatedConnectionSignatureRequest, domainInfo discovery.DomainInfo) (*api.SignatureInfo, error) {

	acs, err := formats.NewAuthenticatedConnectionSignature(domainInfo.GetStatus().String(), s.originCallsign, request.RequestInfo.InvokingDomain)
	if err != nil {
		return nil, fmt.Errorf("error constructing authenticated connection signature format: %v", err)
	}

	signatureInfo := &api.SignatureInfo{
		FromDomain:     s.originCallsign,
		InvokingDomain: request.RequestInfo.InvokingDomain,
	}

	if !domainInfo.HasSharedSecret() {
		signatureInfo.SignatureMessage = acs.EncodeMessage()
		return signatureInfo, nil
	}

	sharedSecret := domainInfo.SharedSecret()

	err = acs.AddParametersForSignature(sharedSecret.LocalKeyID(), domainInfo.GetAdsCertIdentityDomain(), sharedSecret.RemoteKeyID(), request.Timestamp, request.Nonce)
	if err != nil {
		// TODO: Figure out how we want to expose structured metadata for failed signing ops.
		return nil, fmt.Errorf("error adding signature params: %v", err)
	}

	// TODO: SignatureInfo needs to include the signature operation status.
	signatureInfo.FromKey = sharedSecret.LocalKeyID()
	signatureInfo.ToDomain = domainInfo.GetAdsCertIdentityDomain()
	signatureInfo.ToKey = sharedSecret.RemoteKeyID()
	signatureInfo.SigningStatus = acs.GetStatus()

	message := acs.EncodeMessage()
	bodyHMAC, urlHMAC := generateSignatures(domainInfo, []byte(message), request.RequestInfo.BodyHash[:], request.RequestInfo.UrlHash[:])
	signatureInfo.SignatureMessage = message + formats.EncodeSignatureSuffix(bodyHMAC, urlHMAC)

	return signatureInfo, nil
}

func (s *localAuthenticatedConnectionsSignatory) VerifyAuthenticatedConnection(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {

	startTime := time.Now()
	response := &api.AuthenticatedConnectionVerificationResponse{}

	signatureMessage := request.SignatureMessage[0]
	acs, err := formats.DecodeAuthenticatedConnectionSignature(signatureMessage)
	if err != nil {
		metrics.RecordVerify(adscerterrors.ErrVerifyDecodeSignature)
		return response, fmt.Errorf("signature decode failure: %v", err)
	}

	// Validate invocation hostname matches request
	if acs.GetAttributeInvoking() != request.RequestInfo.InvokingDomain {
		logger.Infof("unrelated signature %s versus %s", acs.GetAttributeInvoking(), request.RequestInfo.InvokingDomain)
		metrics.RecordVerify(adscerterrors.ErrVerifySignatureRequestHostMismatch)
		return response, fmt.Errorf("%w: %s versus %s", *adscerterrors.ErrVerifySignatureRequestHostMismatch, acs.GetAttributeInvoking(), request.RequestInfo.InvokingDomain)
	}

	domainInfos, err := s.counterpartyManager.LookupIdentitiesForDomain(acs.GetAttributeFrom())
	if err != nil {
		logger.Infof("counterparty lookup error")
		metrics.RecordVerify(adscerterrors.ErrVerifyCounterpartyLookup)
		response.VerificationStatus = api.VerificationStatus_VERIFICATION_STATUS_SIGNATORY_INTERNAL_ERROR
		return response, err
	}

	domainInfo := domainInfos[0]
	if !domainInfo.HasSharedSecret() {
		logger.Infof("no shared secret")
		metrics.RecordVerify(adscerterrors.ErrVerifyMissingSharedSecret)
		return response, *adscerterrors.ErrVerifyMissingSharedSecret
	}

	bodyHMAC, urlHMAC := generateSignatures(domainInfo, []byte(acs.EncodeMessage()), request.RequestInfo.BodyHash[:], request.RequestInfo.UrlHash[:])
	response.BodyValid, response.UrlValid = acs.CompareSignatures(bodyHMAC, urlHMAC)

	metrics.RecordVerify(nil)
	metrics.RecordVerifyTime(time.Since(startTime))
	metrics.RecordVerifyOutcome(metrics.VerifyOutcomeTypeBody, response.BodyValid)
	metrics.RecordVerifyOutcome(metrics.VerifyOutcomeTypeUrl, response.UrlValid)
	response.VerificationStatus = api.VerificationStatus_VERIFICATION_STATUS_OK
	return response, nil
}

func generateSignatures(domainInfo discovery.DomainInfo, message []byte, bodyHash []byte, urlHash []byte) ([]byte, []byte) {
	h := hmac.New(sha256.New, domainInfo.SharedSecret().Secret()[:])

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
