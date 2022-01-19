package discovery

import (
	"context"
	"testing"
)

const (
	exampleDomainName = "example1.com"
)

func TestNewDefaultDomainStore(t *testing.T) {
	ctx := context.Background()
	domainStore := NewDefaultDomainStore()

	domainsInIndex, err := domainStore.GetAllDomains(ctx)
	if err != nil {
		t.Fatalf("NewDefaultDomainStore() unexpeted error: %v", err)
	}
	if len(domainsInIndex) != 0 {
		t.Fatalf("NewDefaultDomainStore() expected zero initial domains, found %d", len(domainsInIndex))
	}

	domainInfo, ok, err := domainStore.LookupDomainInfo(ctx, exampleDomainName)
	if err != nil {
		t.Fatalf("LookupDomainInfo() unexpeted error: %v", err)
	}
	if ok {
		t.Fatalf("LookupDomainInfo() unexpected ok")
	}

	// Expecting default value
	if domainInfo.Domain != "" {
		t.Fatalf("LookupDomainInfo() unexpected populated DomainInfo value: %v", domainInfo)
	}

	domainStore.StoreDomainInfo(ctx, initializeDomainInfo(exampleDomainName))

	domainInfo, ok, err = domainStore.LookupDomainInfo(ctx, exampleDomainName)
	if err != nil {
		t.Fatalf("LookupDomainInfo() unexpeted error: %v", err)
	}
	if !ok {
		t.Fatalf("LookupDomainInfo() expected ok")
	}
	if domainInfo.Domain != exampleDomainName {
		t.Fatalf("LookupDomainInfo() unexpected populated DomainInfo value: %v", domainInfo)
	}
}
