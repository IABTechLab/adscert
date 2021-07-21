package signatory

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
	"github.com/benbjohnson/clock"
)

func NewLocalAuthenticatedConnectionsSignatory(
	originCallsign string,
	reader io.Reader,
	clock clock.Clock,
	dnsResolver discovery.DNSResolver,
	domainStore discovery.DomainStore,
	domainCheckInterval time.Duration,
	domainRenewalInterval time.Duration,
	base64PrivateKeys []string) AuthenticatedConnectionsSignatory {

	return &localAuthenticatedConnectionsSignatory{
		originCallsign:      originCallsign,
		secureRandom:        reader,
		clock:               clock,
		counterpartyManager: discovery.NewDefaultDomainIndexer(dnsResolver, domainStore, domainCheckInterval, domainRenewalInterval, base64PrivateKeys),
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
		signatureInfo, err := s.embossSingleMessage(request, domainInfo)
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

func (s *localAuthenticatedConnectionsSignatory) embossSingleMessage(request *api.AuthenticatedConnectionSignatureRequest, domainInfo discovery.DomainInfo) (*api.SignatureInfo, error) {

	sigInfo := &api.SignatureInfo{}
	acs, err := formats.NewAuthenticatedConnectionSignature(domainInfo.GetStatus(), s.originCallsign, request.RequestInfo.InvokingDomain)
	if err != nil {
		acs.SetStatus(formats.StatusErrorOnSignature)
		setSignatureInfoFromAuthenticatedConnection(sigInfo, acs)
		return sigInfo, fmt.Errorf("error constructing authenticated connection signature format: %v", err)
	}

	sharedSecret, hasSecret := domainInfo.GetSharedSecret()
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
		sigInfo.SignatureMessage = acs.EncodeMessage()
		return sigInfo, nil
	}

	acs.SetStatus(formats.StatusOK)
	setSignatureInfoFromAuthenticatedConnection(sigInfo, acs)
	message := acs.EncodeMessage()
	bodyHMAC, urlHMAC := generateSignatures(domainInfo, []byte(message), request.RequestInfo.BodyHash[:], request.RequestInfo.UrlHash[:])
	sigInfo.SignatureMessage = message + formats.EncodeSignatureSuffix(bodyHMAC, urlHMAC)

	return sigInfo, nil
}

func (s *localAuthenticatedConnectionsSignatory) VerifyAuthenticatedConnection(request *api.AuthenticatedConnectionVerificationRequest) (*api.AuthenticatedConnectionVerificationResponse, error) {

	startTime := time.Now()
	response := &api.AuthenticatedConnectionVerificationResponse{}
	checkErrors := []error{}
	checked := false

	for _, signatureInfo := range request.RequestInfo.SignatureInfo {
		acs, err := formats.DecodeAuthenticatedConnectionSignature(signatureInfo.SignatureMessage)
		if err != nil {
			metrics.RecordVerify(adscerterrors.ErrVerifyDecodeSignature)
			response.VerificationOperationStatus = api.VerificationOperationStatus_VERIFICATION_OPERATION_STATUS_MALFORMED_REQUEST
			checkErrors = append(checkErrors, fmt.Errorf("signature decode failure: %v", err))
			continue
		}

		// Validate invocation hostname matches request
		if acs.GetAttributeInvoking() != request.RequestInfo.InvokingDomain {
			logger.Infof("unrelated signature %s versus %s", acs.GetAttributeInvoking(), request.RequestInfo.InvokingDomain)
			metrics.RecordVerify(adscerterrors.ErrVerifySignatureRequestHostMismatch)
			checkErrors = append(checkErrors, fmt.Errorf("%w: %s versus %s", *adscerterrors.ErrVerifySignatureRequestHostMismatch, acs.GetAttributeInvoking(), request.RequestInfo.InvokingDomain))
			continue
		}

		domainInfos, err := s.counterpartyManager.LookupIdentitiesForDomain(acs.GetAttributeFrom())
		if err != nil || len(domainInfos) == 0 {
			logger.Infof("counterparty lookup error")
			metrics.RecordVerify(adscerterrors.ErrVerifyCounterpartyLookup)
			checkErrors = append(checkErrors, fmt.Errorf("%v", *adscerterrors.ErrVerifyCounterpartyLookup))
			continue
		}

		for _, domainInfo := range domainInfos {
			if _, hasSecret := domainInfo.GetSharedSecret(); !hasSecret {
				logger.Infof("no shared secret")
				metrics.RecordVerify(adscerterrors.ErrVerifyMissingSharedSecret)
				checkErrors = append(checkErrors, fmt.Errorf("%v", *adscerterrors.ErrVerifyMissingSharedSecret))
				continue
			}

			metrics.RecordVerify(nil)
			bodyHMAC, urlHMAC := generateSignatures(domainInfo, []byte(acs.EncodeMessage()), request.RequestInfo.BodyHash[:], request.RequestInfo.UrlHash[:])
			response.VerificationInfo.BodyValid, response.VerificationInfo.UrlValid = acs.CompareSignatures(bodyHMAC, urlHMAC)
			checked = true
			break
		}
	}

	metrics.RecordVerifyTime(time.Since(startTime))
	metrics.RecordVerifyOutcome(metrics.VerifyOutcomeTypeBody, response.VerificationInfo.BodyValid)
	metrics.RecordVerifyOutcome(metrics.VerifyOutcomeTypeUrl, response.VerificationInfo.UrlValid)

	if checked {
		// signature has been checked, verification operation is successful (regardless of siganture result)
		response.VerificationOperationStatus = api.VerificationOperationStatus_VERIFICATION_OPERATION_STATUS_OK
		return response, nil
	} else {
		// signature has not been checked due to possibly multiple errors, need to wrap them here
		response.VerificationOperationStatus = api.VerificationOperationStatus_VERIFICATION_OPERATION_STATUS_SIGNATORY_INTERNAL_ERROR
		return response, fmt.Errorf("verification failed: %v errors", len(checkErrors))
	}
}

func generateSignatures(domainInfo discovery.DomainInfo, message []byte, bodyHash []byte, urlHash []byte) ([]byte, []byte) {

	sharedSecret, _ := domainInfo.GetSharedSecret()
	h := hmac.New(sha256.New, sharedSecret.Secret()[:])

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
