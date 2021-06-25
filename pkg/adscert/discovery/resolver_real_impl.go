package discovery

import (
	"context"
	"net"
)

func NewRealDnsResolver() DNSResolver {
	return &realDnsResolver{}
}

type realDnsResolver struct{}

func (r *realDnsResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.LookupTXT(name)
}
