package discovery

import "time"

type DomainIndexer interface {
	LookupIdentitiesForDomain(domain string) ([]DomainInfo, error)
	GetLastRun() time.Time
}
