package signatory

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/benbjohnson/clock"
)

func NewLocalAuthenticatedConnectionsSignatory(
	originCallsign string,
	secureRandom io.Reader,
	clock clock.Clock,
	dnsResolver discovery.DNSResolver,
	domainStore discovery.DomainStore,
	domainCheckInterval time.Duration,
	domainRenewalInterval time.Duration,
	base64PrivateKeys []string) *LocalAuthenticatedConnectionsSignatory {
	if originCallsign != "" {
		for i := range base64PrivateKeys {
			if !strings.Contains(strings.TrimRight(base64PrivateKeys[i], "="), "=") {
				base64PrivateKeys[i] = originCallsign + "=" + base64PrivateKeys[i]
			}
		}
	}
	return &LocalAuthenticatedConnectionsSignatory{
		originCallsign:      originCallsign,
		secureRandom:        secureRandom,
		clock:               clock,
		counterpartyManager: discovery.NewDefaultDomainIndexer(dnsResolver, domainStore, domainCheckInterval, domainRenewalInterval, dedupKeys(base64PrivateKeys)),
	}
}

func dedupKeys(privateKeys []string) []string {
	m := make(map[string]bool)
	for _, k := range privateKeys {
		m[k] = true
	}
	var dedup []string
	for k := range m {
		dedup = append(dedup, k)
	}
	return dedup
}

type LocalAuthenticatedConnectionsSignatory struct {
	originCallsign string
	secureRandom   io.Reader
	clock          clock.Clock

	counterpartyManager discovery.DomainIndexer
}

func (s *LocalAuthenticatedConnectionsSignatory) SignAuthenticatedConnection(request *api.AuthenticatedConnectionSignatureRequest) (*api.AuthenticatedConnectionSignatureResponse, error) {

	var err error
	startTime := s.clock.Now()
	response := &api.AuthenticatedConnectionSignatureResponse{RequestInfo: request.RequestInfo}

	if request.RequestInfo == nil || request.RequestInfo.InvokingDomain == "" || len(request.RequestInfo.UrlHash) == 0 {
		response.SignatureOperationStatus = api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_MALFORMED_REQUEST
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
			response.SignatureOperationStatus = api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_SIGNATORY_INTERNAL_ERROR
			return response, err
		}
	}

	domainInfos, err := s.counterpartyManager.LookupIdentitiesForDomain(request.RequestInfo.InvokingDomain)
	if err != nil || len(domainInfos) == 0 {
		logger.Infof("counterparty lookup error")
		metrics.RecordSigning(adscerterrors.ErrSigningCounterpartyLookup)
		response.SignatureOperationStatus = api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_SIGNATORY_INTERNAL_ERROR
		return response, err
	}

	for _, domainInfo := range domainInfos {
		signatureInfo, err := s.signSingleMessage(request, domainInfo)
		if err != nil {
			metrics.RecordSigning(adscerterrors.ErrSigningEmbossMessage)
			response.SignatureOperationStatus = api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_SIGNATORY_INTERNAL_ERROR
			return response, err
		}
		response.RequestInfo.SignatureInfo = append(response.RequestInfo.SignatureInfo, signatureInfo)
	}

	metrics.RecordSigning(nil)
	metrics.RecordSigningTime(time.Since(startTime))
	response.SignatureOperationStatus = api.SignatureOperationStatus_SIGNATURE_OPERATION_STATUS_OK
	return response, nil
}

func (s *LocalAuthenticatedConnectionsSignatory) signSingleMessage(request *api.AuthenticatedConnectionSignatureRequest, domainInfo discovery.DomainInfo) (*api.SignatureInfo, error) {
	sigInfo := &api.SignatureInfo{}

	var originCallsign string
	if request.RequestInfo.OriginDomain != "" {
		originCallsign = request.RequestInfo.OriginDomain
	} else {
		originCallsign = s.originCallsign
	}
	acs, err := formats.NewAuthenticatedConnectionSignature(formats.StatusOK, originCallsign, request.RequestInfo.InvokingDomain)
	if err != nil {
		acs.SetStatus(formats.StatusErrorOnSignature)
		setSignatureInfoFromAuthenticatedConnection(sigInfo, acs)
		return sigInfo, fmt.Errorf("error constructing authenticated connection signature format: %v", err)
	}

	if domainInfo.GetStatus() != discovery.DomainStatusOK {
		acs.SetStatus(formats.StatusErrorOnSignature)
		setSignatureInfoFromAuthenticatedConnection(sigInfo, acs)
		return sigInfo, fmt.Errorf("domain info is not available: %v", err)
	}

	sharedSecret, hasSecret := domainInfo.GetSharedSecret(originCallsign)
	if hasSecret {
		err = acs.AddParametersForSignature(sharedSecret.LocalKeyID(), domainInfo.GetAdsCertIdentityDomain(), sharedSecret.RemoteKeyID(), request.Timestamp, request.Nonce)
		if err != nil {
			acs.SetStatus(formats.StatusErrorOnSignature)
			setSignatureInfoFromAuthenticatedConnection(sigInfo, acs)
			return sigInfo, fmt.Errorf("error adding signature params: %v", err)
		}

	} else {
		acs.SetStatus(formats.StatusErrorOnSignature)
		setSignatureInfoFromAuthenticatedConnection(sigInfo, acs)
		return sigInfo, nil
	}

	acs.SetStatus(formats.StatusOK)
	setSignatureInfoFromAuthenticatedConnection(sigInfo, acs)
	message := acs.EncodeMessage()
	bodyHMAC, urlHMAC := generateSignatures(originCallsign, domainInfo, []byte(message), request.RequestInfo.BodyHash[:], request.RequestInfo.UrlHash[:])
	sigInfo.SignatureMessage = message + formats.EncodeSignatureSuffix(bodyHMAC, urlHMAC)

	return sigInfo, nil
}

func (s *LocalAuthenticatedConnectionsSignatory) VerifyAuthenticatedConnection(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {

	startTime := s.clock.Now()
	response := &api.AuthenticatedConnectionVerificationResponse{}

	for _, requestInfo := range request.RequestInfo {
		verificationInfo := &api.RequestVerificationInfo{}

		for _, signatureInfo := range requestInfo.SignatureInfo {
			decodeStatus := s.checkSingleSignature(requestInfo, signatureInfo)
			logger.Infof("%v", decodeStatus)
			verificationInfo.SignatureDecodeStatus = append(verificationInfo.SignatureDecodeStatus, decodeStatus)
		}

		response.VerificationInfo = append(response.VerificationInfo, verificationInfo)
	}

	metrics.RecordVerifyTime(time.Since(startTime))
	response.VerificationOperationStatus = api.VerificationOperationStatus_VERIFICATION_OPERATION_STATUS_OK
	return response, nil
}

func (s *LocalAuthenticatedConnectionsSignatory) checkSingleSignature(requestInfo *api.RequestInfo, signatureInfo *api.SignatureInfo) api.SignatureDecodeStatus {

	acs, err := formats.DecodeAuthenticatedConnectionSignature(signatureInfo.SignatureMessage)
	if err != nil {
		metrics.RecordVerify(adscerterrors.ErrVerifyDecodeSignature)
		return api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_SIGNATURE_MALFORMED
	}

	// Validate invocation hostname matches request
	if acs.GetAttributeInvoking() != requestInfo.InvokingDomain {
		logger.Infof("unrelated signature %s versus %s", acs.GetAttributeInvoking(), requestInfo.InvokingDomain)
		metrics.RecordVerify(adscerterrors.ErrVerifySignatureRequestHostMismatch)
		return api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_UNRELATED_SIGNATURE
	}

	domainInfos, err := s.counterpartyManager.LookupIdentitiesForDomain(acs.GetAttributeFrom())
	if err != nil || len(domainInfos) == 0 {
		logger.Infof("counterparty lookup error")
		metrics.RecordVerify(adscerterrors.ErrVerifyCounterpartyLookup)
		return api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_COUNTERPARTY_LOOKUP_ERROR
	}

	for _, domainInfo := range domainInfos {
		if _, hasSecret := domainInfo.GetSharedSecret(requestInfo.OriginDomain); !hasSecret {
			logger.Infof("no shared secret")
			metrics.RecordVerify(adscerterrors.ErrVerifyMissingSharedSecret)
			return api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_NO_SHARED_SECRET_AVAILABLE
		}

		bodyHMAC, urlHMAC := generateSignatures(requestInfo.OriginDomain, domainInfo, []byte(acs.EncodeMessage()), requestInfo.BodyHash[:], requestInfo.UrlHash[:])
		bodyValid, urlValid := acs.CompareSignatures(bodyHMAC, urlHMAC)
		if bodyValid && urlValid {
			metrics.RecordVerify(nil)
			return api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID
		} else if bodyValid {
			metrics.RecordVerify(nil)
			return api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_VALID
		}
	}

	metrics.RecordVerify(adscerterrors.ErrVerifyInvalidSignature)
	return api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_INVALID_SIGNATURE
}

func (s *LocalAuthenticatedConnectionsSignatory) IsHealthy() bool {
	return time.Since(s.counterpartyManager.GetLastRun()) <= 5*time.Minute
}

func generateSignatures(originDomain string, domainInfo discovery.DomainInfo, message []byte, bodyHash []byte, urlHash []byte) ([]byte, []byte) {

	sharedSecret, _ := domainInfo.GetSharedSecret(originDomain)
	h := hmac.New(sha256.New, sharedSecret.Secret()[:])

	h.Write([]byte(message))
	h.Write(bodyHash)
	bodyHMAC := h.Sum(nil)

	h.Write(urlHash)
	urlHMAC := h.Sum(nil)

	return bodyHMAC, urlHMAC
}

func (s *LocalAuthenticatedConnectionsSignatory) generateNonce() (string, error) {
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

func (s *LocalAuthenticatedConnectionsSignatory) GetOriginCallsigns() []string {
	return s.counterpartyManager.GetOriginCallsigns()
}
