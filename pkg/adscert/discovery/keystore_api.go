package discovery

import (
	"context"
)

type KeyStore interface {
	GetAllDomains(ctx context.Context) ([]string, error)
	LookupDomainInfo(ctx context.Context, domain string) (DomainInfo, error)
	StoreDomainInfo(ctx context.Context, domainInfo DomainInfo) error
}
