package dnsresolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// StdResolver adapts net.Resolver. It is used only when no name servers can
// be discovered for Client (Windows). The standard library does not
// distinguish NXDOMAIN from NODATA, so "not found" is reported as an empty
// answer: reporting it as NXDOMAIN would claim that existing domains without
// records of one type do not exist. Response size limits cannot be enforced.
type StdResolver struct {
	Resolver *net.Resolver
}

var _ Resolver = (*StdResolver)(nil)

// errNoData marks a not-found answer that callers turn into an empty result.
var errNoData = errors.New("no data")

func (s *StdResolver) wrap(name, typ string, err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return errNoData
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
		if err = s.wrap(name, "TXT", err); err == errNoData {
			return []string{}, nil
		}
		return nil, err
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
		if err = s.wrap(name, "MX", err); err == errNoData {
			return []MX{}, nil
		}
		return nil, err
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
		if err = s.wrap(name, typ, err); err == errNoData {
			return []netip.Addr{}, nil
		}
		return nil, err
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
		if err = s.wrap(name, "CNAME", err); err == errNoData {
			return "", nil
		}
		return "", err
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
		if err = s.wrap(ReverseName(addr), "PTR", err); err == errNoData {
			return []string{}, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, Trim(n))
	}
	return out, nil
}
