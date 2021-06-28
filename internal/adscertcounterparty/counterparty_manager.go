package adscertcounterparty

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/internal/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/metrics"
)

type counterpartyMap map[string]*counterpartyInfo

type counterpartyManager struct {
	counterparties atomic.Value // contains counterpartyMap instance
	mutex          sync.Mutex
	ticker         *time.Ticker
	cancel         context.CancelFunc
	wakeUp         chan struct{}

	myPrivateKeys     keyMap
	currentPrivateKey keyAlias

	dnsResolver discovery.DNSResolver
}

func NewCounterpartyManager(dnsResolver discovery.DNSResolver, base64PrivateKeys []string) CounterpartyAPI {

	cm := &counterpartyManager{
		ticker:      time.NewTicker(30 * time.Second),
		wakeUp:      make(chan struct{}, 1),
		dnsResolver: dnsResolver,
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

	cm.counterparties.Store(counterpartyMap{})
	cm.startAutoUpdate()
	return cm
}

func (cm *counterpartyManager) LookUpInvocationCounterpartyByHostname(domain string) (InvocationCounterparty, error) {

	// Look up invocation party
	invocationCounterparty := &invocationCounterparty{counterpartyInfo: cm.lookup(domain)}

	if len(invocationCounterparty.counterpartyInfo.signatureCounterpartyDomains) == 0 {
		// We don't yet know who will be the signing counterparties for this
		// domain, so just use its own configuration
		invocationCounterparty.signatureCounterpartyInfo = append(invocationCounterparty.signatureCounterpartyInfo, invocationCounterparty.counterpartyInfo)
	} else {
		// For each identified signature counterparty, look them up
		for _, d := range invocationCounterparty.counterpartyInfo.signatureCounterpartyDomains {
			invocationCounterparty.signatureCounterpartyInfo = append(invocationCounterparty.signatureCounterpartyInfo, cm.lookup(d))
		}
	}

	return invocationCounterparty, nil
}

func (cm *counterpartyManager) LookUpSignatureCounterpartyByCallsign(adsCertCallsign string) (SignatureCounterparty, error) {
	return &signatureCounterparty{counterpartyInfo: cm.lookup(adsCertCallsign)}, nil
}

func (cm *counterpartyManager) SynchronizeForTesting() {
	cm.performUpdateSweep(context.Background())
}

func (cm *counterpartyManager) startAutoUpdate() {
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

func (cm *counterpartyManager) performUpdateSweep(ctx context.Context) {
	logger.Info("Starting ads.cert update sweep")

	for domain := range cm.counterparties.Load().(counterpartyMap) {
		currentCounterpartyState := cm.lookup(domain)

		// Make this timing configurable
		if currentCounterpartyState.lastUpdateTime.Before(time.Now().Add(-300 * time.Second)) {
			logger.Infof("Trying to do an update for domain %s", domain)

			start := time.Now()
			baseSubdomain := "_adscert." + domain

			baseSubdomainRecords, err := cm.dnsResolver.LookupTXT(ctx, baseSubdomain)
			if err != nil {
				logger.Warningf("Error looking up record for %s in %v: %v", baseSubdomainRecords, time.Since(start), err)
			} else {
				logger.Infof("Found text record for %s in %v: %v", baseSubdomain, time.Since(start), baseSubdomainRecords)
				metrics.RecordDNSLookupTime(time.Since(start))

				adsCertPolicy, err := formats.DecodeAdsCertPolicyRecord(baseSubdomainRecords[0])
				if err != nil {
					logger.Warningf("Error parsing ads.cert policy record for %s: %v", baseSubdomain, err)
					metrics.RecordDNSLookup(adscerterrors.ErrDNSDecodePolicy)
				} else {
					metrics.RecordDNSLookup(nil)
					// TODO: Evaluate adding support for multiple signature domains.
					currentCounterpartyState.signatureCounterpartyDomains = []string{adsCertPolicy.CanonicalCallsignDomain}

					// Notify that we are interested in this domain if it's the first time we've seen it.
					cm.lookup(adsCertPolicy.CanonicalCallsignDomain)
				}
			}

			start = time.Now()
			deliverySubdomain := "_delivery." + baseSubdomain
			deliverySubdomainRecords, err := cm.dnsResolver.LookupTXT(ctx, deliverySubdomain)

			if err != nil {
				logger.Warningf("Error looking up record for %s in %v: %v", deliverySubdomain, time.Since(start), err)
			} else {
				logger.Infof("Found text record for %s in %v: %v", deliverySubdomain, time.Since(start), deliverySubdomainRecords)
				metrics.RecordDNSLookupTime(time.Since(start))

				// Assume one and only one TXT record
				adsCertKeys, err := formats.DecodeAdsCertKeysRecord(deliverySubdomainRecords[0])
				if err != nil {
					logger.Warningf("Error parsing ads.cert record for %s: %v", deliverySubdomain, err)
					metrics.RecordDNSLookup(adscerterrors.ErrDNSDecodeKeys)
				} else if len(adsCertKeys.PublicKeys) > 0 {
					metrics.RecordDNSLookup(nil)
					currentCounterpartyState.allPublicKeys = asKeyMap(*adsCertKeys)
					currentCounterpartyState.currentPublicKeyId = keyAlias(adsCertKeys.PublicKeys[0].KeyAlias)

					currentCounterpartyState.allSharedSecrets = keyPairMap{}
					currentCounterpartyState.currentSharedSecretId = keyPairAlias{}
				}
			}

			for _, myKey := range cm.myPrivateKeys {
				for _, theirKey := range currentCounterpartyState.allPublicKeys {
					keyPairAlias := newKeyPairAlias(myKey.alias, theirKey.alias)
					if currentCounterpartyState.allSharedSecrets[keyPairAlias] == nil {
						currentCounterpartyState.allSharedSecrets[keyPairAlias], err = calculateSharedSecret(myKey, theirKey)
					}
				}
			}

			currentCounterpartyState.currentSharedSecretId = newKeyPairAlias(cm.currentPrivateKey, currentCounterpartyState.currentPublicKeyId)
			currentCounterpartyState.lastUpdateTime = time.Now()
			cm.update(domain, currentCounterpartyState)
		} else {
			logger.Infof("skipping update for domain %s which is already up to date.", domain)
		}
	}
}

func (cm *counterpartyManager) StopAutoUpdate() {
	cm.ticker.Stop()
	cm.cancel()
}

func (cm *counterpartyManager) UpdateNow() {
	select {
	case cm.wakeUp <- struct{}{}:
		logger.Info("Wrote to wake-up channel.")
		// Channel publish succeeded.
	default:
		// Channel already has pending wake-up call.
		logger.Infof("Didn't write to wake-up channel since there's a request pending")
	}
}

func (cm *counterpartyManager) lookup(domain string) counterpartyInfo {
	counterparty := cm.counterparties.Load().(counterpartyMap)[domain]

	if counterparty != nil {
		return *counterparty
	}

	return cm.register(domain)
}

func (cm *counterpartyManager) register(domain string) counterpartyInfo {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// We may encounter a race condition on registration, so check map again
	// after we acquire a lock.
	counterparty := cm.counterparties.Load().(counterpartyMap)[domain]
	if counterparty != nil {
		return *counterparty
	}

	counterparty = buildInitialCounterparty(domain)
	cm.unsafeStore(domain, counterparty)
	cm.UpdateNow()
	return *counterparty
}

func (cm *counterpartyManager) update(domain string, updatedCounterparty counterpartyInfo) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.unsafeStore(domain, &updatedCounterparty)
}

func (cm *counterpartyManager) unsafeStore(domain string, newCounterparty *counterpartyInfo) {
	currentMap := cm.counterparties.Load().(counterpartyMap)
	newMap := make(counterpartyMap)
	for k, v := range currentMap {
		newMap[k] = v
	}
	newMap[domain] = newCounterparty
	cm.counterparties.Store(newMap)
}

func buildInitialCounterparty(domain string) *counterpartyInfo {
	return &counterpartyInfo{
		domain: domain,
	}
}
