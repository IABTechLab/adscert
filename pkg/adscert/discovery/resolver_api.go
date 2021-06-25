package discovery

import "context"

type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}
