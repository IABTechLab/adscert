package discovery

import (
	"context"
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

type domainMap map[string]DomainInfo

// GetAllDomains returns a list of all stored domain names
func (ds *defaultDomainStore) GetAllDomains(ctx context.Context) ([]string, error) {
	var domains = make([]string, 0)
	for k := range ds.domainMap.Load().(domainMap) {
		domains = append(domains, k)
	}
	return domains, nil
}

// LookupDomainInfo retrives the invoking or identity details for a domain name
func (ds *defaultDomainStore) LookupDomainInfo(ctx context.Context, domain string) (DomainInfo, bool, error) {
	domainInfo, ok := ds.domainMap.Load().(domainMap)[domain]
	// no errors happen for in-memory lookup so elide result and existence status without any error checks
	return domainInfo, ok, nil
}

// StoreDomainInfo stores the invoking or identity details for a domain.
func (ds *defaultDomainStore) StoreDomainInfo(ctx context.Context, domainInfo DomainInfo) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	// Perform a copy and swap operation to replace the current value with a new
	// one using an atomic pointer swap.
	currentMap := ds.domainMap.Load().(domainMap)
	newMap := make(domainMap)
	for k, v := range currentMap {
		newMap[k] = v
	}
	newMap[domainInfo.Domain] = domainInfo
	ds.domainMap.Store(newMap)

	return nil
}
