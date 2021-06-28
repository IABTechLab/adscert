package discovery

import (
	"context"
	"errors"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
)

func NewDefaultDomainIndexer(dnsResolver DNSResolver, domainStore DomainStore, base64PrivateKeys []string) DomainIndexer {

	cm := &defaultDomainIndexer{
		ticker:      time.NewTicker(30 * time.Second),
		wakeUp:      make(chan struct{}, 1),
		dnsResolver: dnsResolver,
		domainStore: domainStore,
	}

	myPrivateKeys, err := privateKeysToKeyMap(base64PrivateKeys)
	if err != nil {
		logger.Fatalf("Error parsing private keys: %v", err)
	}
	cm.myPrivateKeys = myPrivateKeys

	for _, privateKey := range cm.myPrivateKeys {
		// since iterating over a map is non-deterministic, we can make sure to set the key
		// either if it is not already set or it is alphabetically less than current key at the index when
		// iterating over the private keys map.
		if cm.currentPrivateKey == "" || cm.currentPrivateKey < privateKey.alias {
			cm.currentPrivateKey = privateKey.alias
		}
	}

	cm.startAutoUpdate()
	return cm
}

type defaultDomainIndexer struct {
	ticker *time.Ticker
	cancel context.CancelFunc
	wakeUp chan struct{}

	myPrivateKeys     keyMap
	currentPrivateKey keyAlias

	dnsResolver DNSResolver
	domainStore DomainStore
}

func (cm *defaultDomainIndexer) LookupIdentitiesForDomain(invokingDomain string) ([]DomainInfo, error) {

	domainInfo, err := cm.domainStore.LookupDomainInfo(context.Background(), invokingDomain)
	if err != nil {
		return []DomainInfo{}, err
	}

	// if this domain contains public keys then its an identity domain
	// return this domain info directly
	if len(domainInfo.allPublicKeys) > 0 {
		return []DomainInfo{domainInfo}, nil
	}

	// this domain is an invoking domain with (one or many) parent identity domains
	// loop through and request domain info for each identity
	if len(domainInfo.IdentityDomains) > 0 {
		var info []DomainInfo
		for _, d := range domainInfo.IdentityDomains {
			if di, err := cm.domainStore.LookupDomainInfo(context.Background(), d); err == nil {
				info = append(info, di)
			}
		}

		return info, nil
	}

	return nil, errors.New("failed to lookup identity domains for invoking domain")
}

func (cm *defaultDomainIndexer) startAutoUpdate() {
	var ctx context.Context
	ctx, cm.cancel = context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				logger.Info("shutting down auto-update")
				return
			case <-cm.ticker.C:
				logger.Info("automatic wake-up")
			case <-cm.wakeUp:
				logger.Info("manual wake-up from wake-up signal")
			}
			cm.performUpdateSweep(ctx)
		}
	}()
}

func (cm *defaultDomainIndexer) performUpdateSweep(ctx context.Context) {

	logger.Info("Starting ads.cert update sweep")
	domains, err := cm.domainStore.GetAllDomains(ctx)
	if err != nil {
		logger.Warningf("Error retriving list of domains: %v", err)
	}

	for _, domain := range domains {

		currentDomainInfo, err := cm.domainStore.LookupDomainInfo(ctx, domain)
		if err != nil {
			logger.Infof("unable to retrieve domain info for domain %s, skipping update until next loop", domain)

		} else if currentDomainInfo.lastUpdateTime.Before(time.Now().Add(-300 * time.Second)) {
			logger.Infof("Trying to do an update for domain %s", domain)

			cm.checkDomainForPolicyRecords(ctx, &currentDomainInfo)
			cm.checkDomainForKeyRecords(ctx, &currentDomainInfo)

			cm.domainStore.StoreDomainInfo(ctx, currentDomainInfo)

		} else {
			logger.Infof("skipping update for domain %s which is already up to date.", domain)
		}
	}
}

func (cm *defaultDomainIndexer) checkDomainForPolicyRecords(ctx context.Context, currentDomainInfo *DomainInfo) {

	startTime := time.Now()
	baseSubdomain := "_adscert." + currentDomainInfo.Domain
	baseSubdomainRecords, err := cm.dnsResolver.LookupTXT(ctx, baseSubdomain)

	if err != nil {
		logger.Warningf("Error looking up record for %s in %v: %v", baseSubdomainRecords, time.Since(startTime), err)
		return

	} else {
		logger.Infof("Found text record for %s in %v: %v", baseSubdomain, time.Since(startTime), baseSubdomainRecords)
		metrics.RecordDNSLookupTime(time.Since(startTime))

		adsCertPolicy, err := formats.DecodeAdsCertPolicyRecord(baseSubdomainRecords[0])
		if err != nil {
			logger.Warningf("Error parsing ads.cert policy record for %s: %v", baseSubdomain, err)
			metrics.RecordDNSLookup(adscerterrors.ErrDNSDecodePolicy)

		} else {
			currentDomainInfo.IdentityDomains = append(currentDomainInfo.IdentityDomains, adsCertPolicy.CanonicalCallsignDomain)
			metrics.RecordDNSLookup(nil)
		}
	}

	currentDomainInfo.lastUpdateTime = time.Now()
}

func (cm *defaultDomainIndexer) checkDomainForKeyRecords(ctx context.Context, currentDomainInfo *DomainInfo) {

	startTime := time.Now()
	deliverySubdomain := "_delivery._adscert." + currentDomainInfo.Domain
	deliverySubdomainRecords, err := cm.dnsResolver.LookupTXT(ctx, deliverySubdomain)

	if err != nil {
		logger.Warningf("Error looking up record for %s in %v: %v", deliverySubdomain, time.Since(startTime), err)
		return

	} else {
		logger.Infof("Found text record for %s in %v: %v", deliverySubdomain, time.Since(startTime), deliverySubdomainRecords)
		metrics.RecordDNSLookupTime(time.Since(startTime))

		// Assume one and only one TXT record
		adsCertKeys, err := formats.DecodeAdsCertKeysRecord(deliverySubdomainRecords[0])
		if err != nil {
			logger.Warningf("Error parsing ads.cert record for %s: %v", deliverySubdomain, err)
			metrics.RecordDNSLookup(adscerterrors.ErrDNSDecodeKeys)

		} else if len(adsCertKeys.PublicKeys) > 0 {
			currentDomainInfo.allPublicKeys = asKeyMap(*adsCertKeys)
			currentDomainInfo.currentPublicKeyId = keyAlias(adsCertKeys.PublicKeys[0].KeyAlias)
			currentDomainInfo.allSharedSecrets = keyPairMap{}
			currentDomainInfo.currentSharedSecretId = keyPairAlias{}
			metrics.RecordDNSLookup(nil)
		}
	}

	// create shared secrets for each private key + public key combination
	for _, myKey := range cm.myPrivateKeys {
		for _, theirKey := range currentDomainInfo.allPublicKeys {
			keyPairAlias := newKeyPairAlias(myKey.alias, theirKey.alias)
			if currentDomainInfo.allSharedSecrets[keyPairAlias] == nil {
				currentDomainInfo.allSharedSecrets[keyPairAlias], err = calculateSharedSecret(myKey, theirKey)
				if err != nil {
					logger.Warningf("error calculating shared secret for record %s: %v", currentDomainInfo.Domain, err)
				}
			}
		}
	}

	currentDomainInfo.currentSharedSecretId = newKeyPairAlias(cm.currentPrivateKey, currentDomainInfo.currentPublicKeyId)
	currentDomainInfo.lastUpdateTime = time.Now()
}

func (cm *defaultDomainIndexer) StopAutoUpdate() {
	cm.ticker.Stop()
	cm.cancel()
}

func (cm *defaultDomainIndexer) UpdateNow() {
	select {
	case cm.wakeUp <- struct{}{}:
		logger.Info("Wrote to wake-up channel.")
		// Channel publish succeeded.
	default:
		// Channel already has pending wake-up call.
		logger.Infof("Didn't write to wake-up channel since there's a request pending")
	}
}
