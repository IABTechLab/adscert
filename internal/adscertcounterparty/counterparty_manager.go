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

type counterpartyInfo struct {
	registerableDomain  string
	currentPublicKey    keyAlias
	currentSharedSecret keyTupleAlias
	lastUpdateTime      time.Time

	allPublicKeys    keyMap
	allSharedSecrets keyTupleMap

	signatureCounterpartyDomains []string
}

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
	// Curtis notes:
	//
	// The current state of the counterparty manager isn't ideal since it doesn't have a good
	// separation of concerns.  The design doc outlines a better structure where the DNS crawl
	// process and shared secret indexing process are split out from each other, letting the
	// counterparty manager focus on just maintaining a replica of the shared secret cache +
	// the DNS crawl interest list.

	cm := &counterpartyManager{
		ticker:      time.NewTicker(30 * time.Second), //TODO Make this configurable.
		wakeUp:      make(chan struct{}, 1),
		dnsResolver: dnsResolver,
	}

	// TODO: properly read in private key.
	myPrivateKeys, err := privateKeysToKeyMap(base64PrivateKeys)
	if err != nil {
		logger.Fatalf("Error parsing private keys: %v", err)
	}
	cm.myPrivateKeys = myPrivateKeys

	// TODO: properly be able to identify the current private key to use.
	//
	// Curtis notes:
	// See the design doc for the keyring configuration file concepts and key lifecycle state
	// machine. Basically we want to use the key in the KEY_STATUS_ACTIVE_PRIMARY state, as
	// it has been published in DNS for adequate time for counterparties verifying our signature
	// to have crawled it from DNS.
	//
	// Ideally rotation to a new signing key doesn't happen all-at-once but can instead be rolled
	// out in a controlled fashion.
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

type invocationCounterparty struct {
	counterpartyInfo          counterpartyInfo
	signatureCounterpartyInfo []counterpartyInfo
}

func (c *invocationCounterparty) GetStatus() CounterpartyStatus {
	return StatusUnspecified
}

func (c *invocationCounterparty) GetSignatureCounterparties() []SignatureCounterparty {
	result := []SignatureCounterparty{}

	for _, counterparty := range c.signatureCounterpartyInfo {
		result = append(result, &signatureCounterparty{counterpartyInfo: counterparty})
	}

	return result
}

type signatureCounterparty struct {
	counterpartyInfo counterpartyInfo
}

func (c *signatureCounterparty) GetAdsCertIdentityDomain() string {
	return c.counterpartyInfo.registerableDomain
}

func (c *signatureCounterparty) GetStatus() CounterpartyStatus {
	return StatusUnspecified
}

func (c *signatureCounterparty) HasSharedSecret() bool {
	return c.counterpartyInfo.allSharedSecrets[c.counterpartyInfo.currentSharedSecret] != nil
}

func (c *signatureCounterparty) SharedSecret() SharedSecret {
	if !c.HasSharedSecret() {
		return nil
	}
	sharedSecret := c.counterpartyInfo.allSharedSecrets[c.counterpartyInfo.currentSharedSecret]
	return SharedSecret(sharedSecret)
}

func (c *signatureCounterparty) KeyID() string {
	return "a1b2c3"
}

func (cm *counterpartyManager) LookUpInvocationCounterpartyByHostname(invocationHostname string) (InvocationCounterparty, error) {
	// Look up invocation party
	invocationCounterparty := &invocationCounterparty{counterpartyInfo: cm.lookup(invocationHostname)}

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
					currentCounterpartyState.currentPublicKey = keyAlias(adsCertKeys.PublicKeys[0].KeyAlias)

					currentCounterpartyState.allSharedSecrets = keyTupleMap{}
					currentCounterpartyState.currentSharedSecret = keyTupleAlias{}
				}
			}

			for _, myKey := range cm.myPrivateKeys {
				for _, theirKey := range currentCounterpartyState.allPublicKeys {
					keyTupleAlias := newKeyTupleAlias(myKey.alias, theirKey.alias)
					if currentCounterpartyState.allSharedSecrets[keyTupleAlias] == nil {
						currentCounterpartyState.allSharedSecrets[keyTupleAlias], err = calculateSharedSecret(myKey, theirKey)
					}
				}
			}

			currentCounterpartyState.currentSharedSecret = newKeyTupleAlias(cm.currentPrivateKey, currentCounterpartyState.currentPublicKey)
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

func (cm *counterpartyManager) lookup(registerableDomain string) counterpartyInfo {
	counterparty := cm.counterparties.Load().(counterpartyMap)[registerableDomain]

	if counterparty != nil {
		return *counterparty
	}

	return cm.register(registerableDomain)
}

func (cm *counterpartyManager) register(registerableDomain string) counterpartyInfo {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// We may encounter a race condition on registration, so check map again
	// after we acquire a lock.
	counterparty := cm.counterparties.Load().(counterpartyMap)[registerableDomain]
	if counterparty != nil {
		return *counterparty
	}

	counterparty = buildInitialCounterparty(registerableDomain)
	cm.unsafeStore(registerableDomain, counterparty)
	cm.UpdateNow()
	return *counterparty
}

func (cm *counterpartyManager) update(registerableDomain string, updatedCounterparty counterpartyInfo) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.unsafeStore(registerableDomain, &updatedCounterparty)
}

func (cm *counterpartyManager) unsafeStore(registerableDomain string, newCounterparty *counterpartyInfo) {
	currentMap := cm.counterparties.Load().(counterpartyMap)
	newMap := make(counterpartyMap)
	for k, v := range currentMap {
		newMap[k] = v
	}
	newMap[registerableDomain] = newCounterparty
	cm.counterparties.Store(newMap)
}

func buildInitialCounterparty(registerableDomain string) *counterpartyInfo {
	return &counterpartyInfo{
		registerableDomain: registerableDomain,
	}
}
