package discovery

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

func NewDefaultDomainStore() DomainStore {
	store := &defaultDomainStore{}
	// initialize atomic value store
	store.domainMap.Store(domainMap{})
	return store
}

type defaultDomainStore struct {
	domainMap atomic.Value // contains type <domainMap>
	mutex     sync.Mutex
}

type domainMap map[string]*DomainInfo

// GetAllDomains returns a list of all stored domain names
func (ks *defaultDomainStore) GetAllDomains(ctx context.Context) ([]string, error) {
	var domains = make([]string, 0)
	for k := range ks.domainMap.Load().(domainMap) {
		domains = append(domains, k)
	}
	return domains, nil
}

// LookupDomainInfo retrives the invoking or identity details for a domain name
func (ks *defaultDomainStore) LookupDomainInfo(ctx context.Context, domain string) (DomainInfo, error) {
	if domainInfo, ok := ks.domainMap.Load().(domainMap)[domain]; ok {
		return *domainInfo, nil
	}
	return DomainInfo{Domain: domain}, errors.New("domain information could not be found")
}

// StoreDomainInfo stores the invoking or identity details for a domain
func (ks *defaultDomainStore) StoreDomainInfo(ctx context.Context, domainInfo DomainInfo) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	currentMap := ks.domainMap.Load().(domainMap)
	newMap := make(domainMap)
	for k, v := range currentMap {
		newMap[k] = v
	}
	newMap[domainInfo.Domain] = &domainInfo
	ks.domainMap.Store(newMap)

	return nil
}
