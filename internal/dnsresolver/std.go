package dnsresolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// StdResolver adapts net.Resolver. It is used only when no name servers can
// be discovered for Client. The standard library does not distinguish
// NXDOMAIN from NODATA reliably, so both are reported as KindNXDomain, and
// response size limits cannot be enforced.
type StdResolver struct {
	Resolver *net.Resolver
}

var _ Resolver = (*StdResolver)(nil)

func (s *StdResolver) wrap(name, typ string, err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return &Error{Kind: KindNXDomain, Name: Trim(name), Type: typ}
		case dnsErr.IsTimeout, dnsErr.IsTemporary:
			return &Error{Kind: KindTemporary, Name: Trim(name), Type: typ, Err: err}
		}
	}
	return &Error{Kind: KindTemporary, Name: Trim(name), Type: typ, Err: err}
}

// LookupTXT implements Resolver.
func (s *StdResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if !ValidDomain(name) {
		return nil, &Error{Kind: KindInvalidName, Name: name, Type: "TXT"}
	}
	txt, err := s.Resolver.LookupTXT(ctx, Fqdn(name))
	if err != nil {
		return nil, s.wrap(name, "TXT", err)
	}
	return txt, nil
}

// LookupMX implements Resolver.
func (s *StdResolver) LookupMX(ctx context.Context, name string) ([]MX, error) {
	if !ValidDomain(name) {
		return nil, &Error{Kind: KindInvalidName, Name: name, Type: "MX"}
	}
	mxs, err := s.Resolver.LookupMX(ctx, Fqdn(name))
	if err != nil {
		return nil, s.wrap(name, "MX", err)
	}
	out := make([]MX, 0, len(mxs))
	for _, mx := range mxs {
		out = append(out, MX{Host: Trim(mx.Host), Preference: mx.Pref})
	}
	return out, nil
}

func (s *StdResolver) lookupIP(ctx context.Context, network, name, typ string) ([]netip.Addr, error) {
	if !ValidDomain(name) {
		return nil, &Error{Kind: KindInvalidName, Name: name, Type: typ}
	}
	addrs, err := s.Resolver.LookupNetIP(ctx, network, Fqdn(name))
	if err != nil {
		return nil, s.wrap(name, typ, err)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	return out, nil
}

// LookupA implements Resolver.
func (s *StdResolver) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	return s.lookupIP(ctx, "ip4", name, "A")
}

// LookupAAAA implements Resolver.
func (s *StdResolver) LookupAAAA(ctx context.Context, name string) ([]netip.Addr, error) {
	return s.lookupIP(ctx, "ip6", name, "AAAA")
}

// LookupCNAME implements Resolver.
func (s *StdResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	if !ValidDomain(name) {
		return "", &Error{Kind: KindInvalidName, Name: name, Type: "CNAME"}
	}
	cname, err := s.Resolver.LookupCNAME(ctx, Fqdn(name))
	if err != nil {
		return "", s.wrap(name, "CNAME", err)
	}
	if strings.EqualFold(Fqdn(cname), Fqdn(name)) {
		return "", nil
	}
	return Trim(cname), nil
}

// LookupPTR implements Resolver.
func (s *StdResolver) LookupPTR(ctx context.Context, addr netip.Addr) ([]string, error) {
	names, err := s.Resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		return nil, s.wrap(ReverseName(addr), "PTR", err)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, Trim(n))
	}
	return out, nil
}
