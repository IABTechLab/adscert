package discovery

import (
	"context"
	"net"
)

func NewDefaultDnsResolver() DNSResolver {
	return &defaultDnsResolver{}
}

type defaultDnsResolver struct{}

func (r *defaultDnsResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.LookupTXT(name)
}
