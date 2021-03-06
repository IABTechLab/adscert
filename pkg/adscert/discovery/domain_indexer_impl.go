package discovery

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/utils"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
)

func NewDefaultDomainIndexer(dnsResolver DNSResolver, domainStore DomainStore, domainCheckInterval time.Duration, domainRenewalInterval time.Duration, base64PrivateKeys []string) DomainIndexer {

	// check domains every 30 seconds by default
	if domainCheckInterval <= 0 {
		domainCheckInterval = 30 * time.Second
	}

	// renew domains after 5 minutes by default
	if domainRenewalInterval <= 0 {
		domainRenewalInterval = 300 * time.Second
	}

	di := &defaultDomainIndexer{
		ticker:                time.NewTicker(domainCheckInterval),
		wakeUp:                make(chan struct{}, 1),
		domainRenewalInterval: domainRenewalInterval,
		dnsResolver:           dnsResolver,
		domainStore:           domainStore,
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
	di.UpdateNow()
	return di
}

type defaultDomainIndexer struct {
	ticker                *time.Ticker
	cancel                context.CancelFunc
	wakeUp                chan struct{}
	domainRenewalInterval time.Duration

	lastRun     time.Time
	lastRunLock sync.RWMutex

	myPrivateKeys     keyMap
	currentPrivateKey keyAlias

	dnsResolver DNSResolver
	domainStore DomainStore
}

func (di *defaultDomainIndexer) GetLastRun() time.Time {
	di.lastRunLock.RLock()
	t := di.lastRun
	di.lastRunLock.RUnlock()
	return t
}

func (di *defaultDomainIndexer) updateLastRun() {
	di.lastRunLock.Lock()
	di.lastRun = time.Now()
	di.lastRunLock.Unlock()
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
		di.domainStore.StoreDomainInfo(context.Background(), initializeDomainInfo(invokingDomain))
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
			di.updateLastRun()
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

		} else if currentDomainInfo.lastUpdateTime.Before(time.Now().Add(di.domainRenewalInterval)) {
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
		logger.Warningf("No record found for %s in %v: %v", baseSubdomain, time.Since(startTime), err)
		return

	} else {
		logger.Infof("Found records for %s in %v: %v", baseSubdomain, time.Since(startTime), baseSubdomainRecords)
		metrics.RecordDNSLookupTime(time.Since(startTime))

		if foundDomains, parseError := parsePolicyRecords(baseSubdomain, baseSubdomainRecords); parseError {
			currentDomainInfo.domainStatus = DomainStatusADPFParseError
		} else {
			// replace current domain info with new identity domains (and filter to keep uniques)
			currentDomainInfo.IdentityDomains = foundDomains
			currentDomainInfo.IdentityDomains = utils.MergeUniques(currentDomainInfo.IdentityDomains)
			currentDomainInfo.domainStatus = DomainStatusOK
		}
	}

	// loop through and ensure that all identity domains are also stored for processing and lookup
	for _, domain := range currentDomainInfo.IdentityDomains {
		if _, ok, _ := di.domainStore.LookupDomainInfo(ctx, domain); !ok {
			di.domainStore.StoreDomainInfo(ctx, initializeDomainInfo(domain))
			di.UpdateNow()
		}
	}

	currentDomainInfo.lastUpdateTime = time.Now()
}

func (di *defaultDomainIndexer) checkDomainForKeyRecords(ctx context.Context, currentDomainInfo *DomainInfo) {

	startTime := time.Now()
	deliverySubdomain := "_delivery._adscert." + currentDomainInfo.Domain
	deliverySubdomainRecords, err := di.dnsResolver.LookupTXT(ctx, deliverySubdomain)

	if err != nil {
		logger.Warningf("No record found for %s in %v: %v", deliverySubdomain, time.Since(startTime), err)
		return

	} else {
		logger.Infof("Found records for %s in %v: %v", deliverySubdomain, time.Since(startTime), deliverySubdomainRecords)
		metrics.RecordDNSLookupTime(time.Since(startTime))

		if foundKeys, parseError := parseKeyRecords(deliverySubdomain, deliverySubdomainRecords); parseError {
			currentDomainInfo.domainStatus = DomainStatusADCRTDParseError
		} else {
			// replace current domain info with new public keys
			currentDomainInfo.allPublicKeys = asKeyMap(formats.AdsCertKeys{PublicKeys: foundKeys})
			currentDomainInfo.currentPublicKeyId = keyAlias(foundKeys[0].KeyAlias)
			currentDomainInfo.domainStatus = DomainStatusOK
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
					currentDomainInfo.domainStatus = DomainStatusErrorOnSharedSecretCalculation
				}
			}
		}
	}

	currentDomainInfo.currentSharedSecretId = newKeyPairAlias(di.currentPrivateKey, currentDomainInfo.currentPublicKeyId)
	currentDomainInfo.lastUpdateTime = time.Now()
}

func parsePolicyRecords(baseSubdomain string, baseSubdomainRecords []string) (foundDomains []string, parseError bool) {

	// log warning if there are multiple policy records found because there should only be a single authoritative identity domain
	// however this is not an error because there may be multiple records during a ownerhsip change
	if len(baseSubdomainRecords) > 1 {
		logger.Warningf("Found multiple policy records for %s: %v", baseSubdomain, baseSubdomainRecords)
	}

	for _, v := range baseSubdomainRecords {
		if adsCertPolicy, err := formats.DecodeAdsCertPolicyRecord(v); err != nil {
			logger.Warningf("Error parsing ads.cert policy record for %s: %v", baseSubdomain, err)
			metrics.RecordDNSLookup(adscerterrors.ErrDNSDecodePolicy)
			parseError = true

		} else {
			foundDomains = append(foundDomains, adsCertPolicy.CanonicalCallsignDomain)
			metrics.RecordDNSLookup(nil)
		}
	}

	return foundDomains, parseError
}

func parseKeyRecords(deliverySubdomain string, deliverySubdomainRecords []string) (foundKeys []formats.ParsedPublicKey, parseError bool) {

	// log warning if there are multiple key records found
	// however this is not an error because there may be multiple records as keys are aged out and/or records become large
	if len(deliverySubdomainRecords) > 1 {
		logger.Warningf("Found multiple key records for %s: %v", deliverySubdomain, deliverySubdomainRecords)
	}

	for _, v := range deliverySubdomainRecords {
		adsCertKeys, err := formats.DecodeAdsCertKeysRecord(v)
		if err != nil {
			logger.Warningf("Error parsing ads.cert key record for %s: %v", deliverySubdomain, err)
			metrics.RecordDNSLookup(adscerterrors.ErrDNSDecodeKeys)
			parseError = true

		} else if len(adsCertKeys.PublicKeys) > 0 {
			foundKeys = append(foundKeys, adsCertKeys.PublicKeys...)
			metrics.RecordDNSLookup(nil)
		}
	}

	return foundKeys, parseError
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

func initializeDomainInfo(domain string) DomainInfo {
	return DomainInfo{
		Domain:                domain,
		IdentityDomains:       []string{},
		currentPublicKeyId:    "",
		currentSharedSecretId: keyPairAlias{},
		allPublicKeys:         map[keyAlias]*x25519Key{},
		allSharedSecrets:      keyPairMap{},
		domainStatus:          DomainStatusNotYetChecked,
		lastUpdateTime:        time.Time{},
	}
}
