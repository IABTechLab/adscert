package discovery

import (
	"context"
)

func NewFakeDnsResolver() DNSResolver {
	return &fakeDnsResolver{fakeRecords: []string{"fake DNS record"}}
}

type fakeDnsResolver struct {
	fakeRecords []string
	fakeError   error
}

func (r *fakeDnsResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.fakeRecords, r.fakeError
}
