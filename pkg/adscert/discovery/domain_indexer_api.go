package discovery

type DomainIndexer interface {
	LookupIdentitiesForDomain(domain string) ([]DomainInfo, error)
}
