// Package mx discovers and validates the mail exchangers of a domain.
package mx

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
	"github.com/marcindolinski/mailauthprobe/internal/netutil"
)

// MaxHosts bounds the number of MX hosts whose addresses are resolved.
const MaxHosts = 32

// Host describes one mail exchanger.
type Host struct {
	Name       string       `json:"name"`
	Preference uint16       `json:"preference"`
	CNAME      string       `json:"cname,omitempty"`
	IPv4       []netip.Addr `json:"ipv4,omitempty"`
	IPv6       []netip.Addr `json:"ipv6,omitempty"`
	Error      string       `json:"error,omitempty"`
}

// Result is the outcome of an MX assessment.
type Result struct {
	Domain string `json:"domain"`
	// Hosts lists MX records sorted by preference and name.
	Hosts []Host `json:"hosts"`
	// NullMX is set when the domain publishes "MX 0 .".
	NullMX bool `json:"null_mx"`
	// Implicit is set when there are no MX records but the domain itself has
	// address records (RFC 5321 section 5.1 implicit MX).
	Implicit bool               `json:"implicit_mx"`
	Findings []findings.Finding `json:"-"`
}

// Assess looks up and validates the MX records of domain. The returned error
// is non-nil only when DNS failures prevented a reliable assessment; the
// result is still usable and contains a finding describing the failure.
func Assess(ctx context.Context, r dnsresolver.Resolver, domain string) (*Result, error) {
	domain = dnsresolver.Trim(domain)
	res := &Result{Domain: domain, Hosts: []Host{}}
	add := func(f findings.Finding) { res.Findings = append(res.Findings, f) }

	records, err := r.LookupMX(ctx, domain)
	switch {
	case dnsresolver.IsNXDomain(err):
		add(findings.MXDomainNotFound.New(domain, fmt.Sprintf("The name %s does not exist in DNS (NXDOMAIN).", domain)))
		return res, nil
	case err != nil:
		add(findings.DNSLookupFailed.New(domain, "The MX lookup failed; MX configuration could not be assessed.", err.Error()))
		return res, err
	}

	if len(records) == 0 {
		return res, assessImplicit(ctx, r, res)
	}

	slices.SortStableFunc(records, func(a, b dnsresolver.MX) int {
		return cmp.Or(cmp.Compare(a.Preference, b.Preference), strings.Compare(a.Host, b.Host))
	})

	var null []dnsresolver.MX
	for _, rec := range records {
		if rec.Host == "." || rec.Host == "" {
			null = append(null, rec)
		}
	}
	if len(null) > 0 {
		res.NullMX = true
		for _, rec := range null {
			if rec.Preference != 0 {
				add(findings.MXNullPreference.New(domain, fmt.Sprintf("The null MX record uses preference %d.", rec.Preference), recordString(rec)))
			}
		}
		if len(null) == len(records) {
			for _, rec := range records {
				res.Hosts = append(res.Hosts, Host{Name: ".", Preference: rec.Preference})
			}
			add(findings.MXNullMX.New(domain, "The domain explicitly declares that it does not accept mail (RFC 7505)."))
			return res, nil
		}
		ev := make([]string, 0, len(records))
		for _, rec := range records {
			ev = append(ev, recordString(rec))
		}
		add(findings.MXNullMixed.New(domain, "A null MX record is published together with other MX records, so senders cannot tell whether the domain accepts mail.", ev...))
	}

	seen := map[string]int{}
	var infraErr error
	checked := 0
	for _, rec := range records {
		if rec.Host == "." || rec.Host == "" {
			res.Hosts = append(res.Hosts, Host{Name: ".", Preference: rec.Preference})
			continue
		}
		name := dnsresolver.Trim(rec.Host)
		seen[name]++
		if seen[name] > 1 {
			continue
		}
		h := Host{Name: name, Preference: rec.Preference}
		if checked >= MaxHosts {
			res.Hosts = append(res.Hosts, h)
			continue
		}
		checked++
		if err := assessHost(ctx, r, domain, &h, add); err != nil && dnsresolver.IsInfrastructure(err) {
			infraErr = err
		}
		res.Hosts = append(res.Hosts, h)
	}
	if checked >= MaxHosts && len(seen) > MaxHosts {
		add(findings.MXTooMany.New(domain, fmt.Sprintf("The domain publishes %d MX hosts; only the first %d were resolved.", len(seen), MaxHosts)))
	}

	for _, h := range res.Hosts {
		if n := seen[h.Name]; n > 1 {
			add(findings.MXDuplicateHost.New(h.Name, fmt.Sprintf("%s appears in %d MX records.", h.Name, n)))
		}
	}

	summarize(res, add)
	return res, infraErr
}

func recordString(rec dnsresolver.MX) string {
	host := rec.Host
	if host != "." {
		host += "."
	}
	return fmt.Sprintf("MX %d %s", rec.Preference, host)
}

func assessImplicit(ctx context.Context, r dnsresolver.Resolver, res *Result) error {
	add := func(f findings.Finding) { res.Findings = append(res.Findings, f) }
	h := Host{Name: res.Domain}
	err := resolveAddresses(ctx, r, &h)
	if err != nil && dnsresolver.IsTemporary(err) {
		add(findings.DNSLookupFailed.New(res.Domain, "Address lookup for implicit MX failed.", err.Error()))
		return err
	}
	if len(h.IPv4)+len(h.IPv6) == 0 {
		add(findings.MXNoMailHost.New(res.Domain, "The domain has no MX records and no A/AAAA records, so it cannot receive mail, but senders are not told so explicitly."))
		return nil
	}
	res.Implicit = true
	res.Hosts = append(res.Hosts, h)
	add(findings.MXNone.New(res.Domain, "The domain has no MX records. Senders will deliver to the domain's own A/AAAA records (implicit MX), which is rarely intended."))
	return nil
}

func assessHost(ctx context.Context, r dnsresolver.Resolver, domain string, h *Host, add func(findings.Finding)) error {
	if addr, err := netip.ParseAddr(strings.Trim(h.Name, "[]")); err == nil {
		add(findings.MXIPLiteral.New(h.Name, fmt.Sprintf("The MX record for %s points at the address %s instead of a host name.", domain, addr)))
		h.Error = "target is an IP address"
		return nil
	}
	if !netutil.IsHostname(h.Name) {
		add(findings.MXInvalidHostname.New(h.Name, fmt.Sprintf("%q is not a valid host name.", h.Name)))
	}

	// A failing CNAME lookup is not reported on its own: if the name is
	// really unusable, the address lookups below fail as well.
	if cname, err := r.LookupCNAME(ctx, h.Name); err == nil && cname != "" {
		h.CNAME = cname
		add(findings.MXCNAME.New(h.Name, fmt.Sprintf("%s is an alias for %s.", h.Name, cname), fmt.Sprintf("%s. CNAME %s.", h.Name, cname)))
	}

	err := resolveAddresses(ctx, r, h)
	if err != nil && dnsresolver.IsTemporary(err) {
		h.Error = err.Error()
		add(findings.MXLookupInconsistent.New(h.Name, fmt.Sprintf("Address lookup for MX host %s failed.", h.Name), err.Error()))
		return err
	}
	if len(h.IPv4)+len(h.IPv6) == 0 {
		reason := "no A or AAAA records"
		if dnsresolver.IsNXDomain(err) {
			reason = "the name does not exist (NXDOMAIN)"
		}
		h.Error = reason
		add(findings.MXNoAddress.New(h.Name, fmt.Sprintf("MX host %s cannot be reached: %s.", h.Name, reason)))
		return nil
	}
	var bad []string
	for _, a := range slices.Concat(h.IPv4, h.IPv6) {
		if netutil.IsNonPublic(a) {
			bad = append(bad, a.String())
		}
	}
	if len(bad) > 0 {
		add(findings.MXNonPublicAddress.New(h.Name, fmt.Sprintf("MX host %s resolves to addresses that are not reachable from the Internet.", h.Name), bad...))
	}
	return nil
}

// resolveAddresses fills h.IPv4 and h.IPv6. It returns the first error that
// is not NODATA; NXDOMAIN is returned only if both lookups report it.
func resolveAddresses(ctx context.Context, r dnsresolver.Resolver, h *Host) error {
	v4, err4 := r.LookupA(ctx, h.Name)
	v6, err6 := r.LookupAAAA(ctx, h.Name)
	h.IPv4, h.IPv6 = sortAddrs(v4), sortAddrs(v6)
	for _, err := range []error{err4, err6} {
		if err != nil && dnsresolver.IsTemporary(err) {
			return err
		}
	}
	if dnsresolver.IsNXDomain(err4) {
		return err4
	}
	return err6
}

func sortAddrs(a []netip.Addr) []netip.Addr {
	if len(a) == 0 {
		return nil
	}
	a = slices.Clone(a)
	slices.SortFunc(a, netip.Addr.Compare)
	return slices.Compact(a)
}

func summarize(res *Result, add func(findings.Finding)) {
	var usable, v6 int
	var names []string
	for _, h := range res.Hosts {
		if h.Name == "." {
			continue
		}
		names = append(names, h.Name)
		if len(h.IPv4)+len(h.IPv6) > 0 {
			usable++
		}
		if len(h.IPv6) > 0 {
			v6++
		}
	}
	if len(names) == 0 {
		return
	}
	if usable == 0 {
		for i, f := range res.Findings {
			if f.ID == findings.MXNoAddress.ID {
				res.Findings[i] = f.WithSeverity(findings.SeverityHigh)
			}
		}
		return
	}
	if v6 == 0 {
		add(findings.MXIPv4Only.New(res.Domain, "None of the MX hosts publish AAAA records; IPv6-only senders cannot deliver mail."))
	}
	if len(names) == 1 {
		add(findings.MXSingleHost.New(res.Domain, fmt.Sprintf("All mail is handled by a single MX host (%s). Consider a backup exchanger if the provider does not already offer redundancy behind that name.", names[0])))
	}
	for _, f := range res.Findings {
		if f.Severity >= findings.SeverityLow {
			return
		}
	}
	add(findings.MXValid.New(res.Domain, fmt.Sprintf("%d MX host(s) resolve to public addresses.", usable), names...))
}
