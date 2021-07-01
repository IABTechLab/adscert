package discovery

import (
	"context"
	"errors"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
)

func NewDefaultDomainIndexer(dnsResolver DNSResolver, domainStore DomainStore, base64PrivateKeys []string) DomainIndexer {

	di := &defaultDomainIndexer{
		ticker:      time.NewTicker(30 * time.Second),
		wakeUp:      make(chan struct{}, 1),
		dnsResolver: dnsResolver,
		domainStore: domainStore,
	}

	myPrivateKeys, err := privateKeysToKeyMap(base64PrivateKeys)
	if err != nil {
		logger.Fatalf("Error parsing private keys: %v", err)
	}
	di.myPrivateKeys = myPrivateKeys

	for _, privateKey := range di.myPrivateKeys {
		// since iterating over a map is non-deterministic, we can make sure to set the key
		// either if it is not already set or it is alphabetically less than current key at the index when
		// iterating over the private keys map.
		if di.currentPrivateKey == "" || di.currentPrivateKey < privateKey.alias {
			di.currentPrivateKey = privateKey.alias
		}
	}

	di.startAutoUpdate()
	return di
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

func (di *defaultDomainIndexer) LookupIdentitiesForDomain(invokingDomain string) ([]DomainInfo, error) {

	domainInfo, ok, err := di.domainStore.LookupDomainInfo(context.Background(), invokingDomain)
	if err != nil {
		// lookup operation had a problem (depends on domain store implementation, for example network failure)
		// return empty list
		return []DomainInfo{}, err
	}
	if !ok {
		// domain was not found in domain store
		// store a new entry so it can be processed and queue an update
		di.domainStore.StoreDomainInfo(context.Background(), DomainInfo{Domain: invokingDomain, lastUpdateTime: time.Now().UTC().Add(-1 * time.Hour)})
		di.UpdateNow()
		// return empty list
		return []DomainInfo{}, nil
	}

	// if this domain contains public keys then its an identity domain
	// return this domain info directly
	if len(domainInfo.allPublicKeys) > 0 {
		return []DomainInfo{domainInfo}, nil
	}

	// this domain is an invoking domain with (one or many) parent identity domains
	// loop through and request domain info for each identity
	if len(domainInfo.IdentityDomains) > 0 {
		var domains []DomainInfo
		for _, d := range domainInfo.IdentityDomains {
			if info, ok, err := di.domainStore.LookupDomainInfo(context.Background(), d); err == nil && ok {
				domains = append(domains, info)
			}
		}

		return domains, nil
	}

	return nil, errors.New("failed to lookup identity domains for invoking domain")
}

func (di *defaultDomainIndexer) startAutoUpdate() {
	var ctx context.Context
	ctx, di.cancel = context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				logger.Info("shutting down auto-update")
				return
			case <-di.ticker.C:
				logger.Info("automatic wake-up")
			case <-di.wakeUp:
				logger.Info("manual wake-up from wake-up signal")
			}
			di.performUpdateSweep(ctx)
		}
	}()
}

func (di *defaultDomainIndexer) performUpdateSweep(ctx context.Context) {

	logger.Info("Starting ads.cert update sweep")
	domains, err := di.domainStore.GetAllDomains(ctx)
	if err != nil {
		logger.Warningf("Error retriving list of domains: %v", err)
	}

	for _, domain := range domains {
		currentDomainInfo, _, err := di.domainStore.LookupDomainInfo(ctx, domain)
		if err != nil {
			logger.Infof("unable to retrieve domain info for domain %s, skipping update until next loop", domain)

		} else if currentDomainInfo.lastUpdateTime.Before(time.Now().Add(-300 * time.Second)) {
			logger.Infof("Trying to do an update for domain %s", domain)
			di.checkDomainForPolicyRecords(ctx, &currentDomainInfo)
			di.checkDomainForKeyRecords(ctx, &currentDomainInfo)
			di.domainStore.StoreDomainInfo(ctx, currentDomainInfo)

		} else {
			logger.Infof("skipping update for domain %s which is already up to date.", domain)
		}
	}
}

func (di *defaultDomainIndexer) checkDomainForPolicyRecords(ctx context.Context, currentDomainInfo *DomainInfo) {

	startTime := time.Now()
	baseSubdomain := "_adscert." + currentDomainInfo.Domain
	baseSubdomainRecords, err := di.dnsResolver.LookupTXT(ctx, baseSubdomain)

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

	// merge identity domains list to avoid infinitely appending to the list
	// loop through and ensure that all identity domains are also stored for processing and lookup
	currentDomainInfo.IdentityDomains = utils.MergeUniques(currentDomainInfo.IdentityDomains)
	for _, domain := range currentDomainInfo.IdentityDomains {
		if _, ok, _ := di.domainStore.LookupDomainInfo(ctx, domain); !ok {
			di.domainStore.StoreDomainInfo(ctx, DomainInfo{Domain: domain})
		}
	}

	currentDomainInfo.lastUpdateTime = time.Now()
}

func (di *defaultDomainIndexer) checkDomainForKeyRecords(ctx context.Context, currentDomainInfo *DomainInfo) {

	startTime := time.Now()
	deliverySubdomain := "_delivery._adscert." + currentDomainInfo.Domain
	deliverySubdomainRecords, err := di.dnsResolver.LookupTXT(ctx, deliverySubdomain)

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
	for _, myKey := range di.myPrivateKeys {
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

	currentDomainInfo.currentSharedSecretId = newKeyPairAlias(di.currentPrivateKey, currentDomainInfo.currentPublicKeyId)
	currentDomainInfo.lastUpdateTime = time.Now()
}

func (di *defaultDomainIndexer) StopAutoUpdate() {
	di.ticker.Stop()
	di.cancel()
}

func (di *defaultDomainIndexer) UpdateNow() {
	select {
	case di.wakeUp <- struct{}{}:
		logger.Info("Wrote to wake-up channel.")
		// Channel publish succeeded.
	default:
		// Channel already has pending wake-up call.
		logger.Infof("Didn't write to wake-up channel since there's a request pending")
	}
}
