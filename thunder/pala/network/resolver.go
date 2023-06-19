package network

import (
	"context"
	"net"
)

type DomainNameResolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

type DomainNameResolverImpl struct {
	resolver net.Resolver
}

func NewDomainNameResolver() DomainNameResolver {
	return &DomainNameResolverImpl{}
}

func (r *DomainNameResolverImpl) LookupHost(
	ctx context.Context, host string) (addrs []string, err error) {
	return r.resolver.LookupHost(ctx, host)
}
