package mtasts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

// Assessment is the MTA-STS part of a domain audit.
type Assessment struct {
	Domain   string    `json:"domain"`
	Records  []string  `json:"records,omitempty"`
	Record   *Record   `json:"record,omitempty"`
	Response *Response `json:"response,omitempty"`
	Policy   *Policy   `json:"policy,omitempty"`
	Error    string    `json:"error,omitempty"`

	Findings []findings.Finding `json:"-"`
}

// Options for Assess.
type Options struct {
	Resolver dnsresolver.Resolver
	Fetcher  Fetcher
	// MXHosts are the domain's MX host names, checked against the policy.
	MXHosts []string
	Now     time.Time
}

// Assess audits MTA-STS for domain.
func Assess(ctx context.Context, domain string, opts Options) (*Assessment, error) {
	domain = dnsresolver.Trim(domain)
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	a := &Assessment{Domain: domain}
	add := func(f findings.Finding) { a.Findings = append(a.Findings, f) }
	name := "_mta-sts." + domain

	txts, err := opts.Resolver.LookupTXT(ctx, name)
	if err != nil && !dnsresolver.IsNXDomain(err) {
		add(findings.DNSLookupFailed.New(name, "The MTA-STS TXT lookup failed.", err.Error()))
		return a, err
	}
	for _, t := range txts {
		if IsSTSRecord(t) {
			a.Records = append(a.Records, t)
		}
	}

	switch len(a.Records) {
	case 0:
		// Look for an orphaned policy only if its host exists, to avoid
		// needless connection attempts.
		host := "mta-sts." + domain
		v4, _ := opts.Resolver.LookupA(ctx, host)
		v6, _ := opts.Resolver.LookupAAAA(ctx, host)
		if len(v4)+len(v6) > 0 && opts.Fetcher != nil {
			if resp, err := opts.Fetcher.Fetch(ctx, domain); err == nil && resp.StatusCode == 200 {
				a.Response = resp
				add(findings.MTASTSPolicyWithoutRecord.New(domain, fmt.Sprintf("A policy is published at %s, but %s has no MTA-STS TXT record, so senders never fetch it.", resp.URL, name)))
				return a, nil
			}
		}
		add(findings.MTASTSMissing.New(domain, fmt.Sprintf("%s does not publish MTA-STS; senders may deliver mail over unauthenticated or plaintext connections.", domain)))
		return a, nil
	case 1:
	default:
		add(findings.MTASTSInvalidRecord.New(name, fmt.Sprintf("%s has %d MTA-STS records; senders treat the domain as not implementing MTA-STS.", name, len(a.Records)), a.Records...))
		return a, nil
	}

	rec, err := ParseRecord(a.Records[0])
	if err != nil {
		a.Error = err.Error()
		add(findings.MTASTSInvalidRecord.New(name, fmt.Sprintf("The MTA-STS record is invalid: %v.", err), a.Records[0]))
		return a, nil
	}
	a.Record = rec
	if opts.Fetcher == nil {
		return a, nil
	}

	resp, err := opts.Fetcher.Fetch(ctx, domain)
	a.Response = resp
	if resp != nil && resp.Certificate != nil {
		if left := resp.Certificate.NotAfter.Sub(opts.Now); left > 0 && left < 14*24*time.Hour {
			add(findings.MTASTSCertExpiring.New("mta-sts."+domain, fmt.Sprintf("The certificate of mta-sts.%s expires on %s.", domain, resp.Certificate.NotAfter.Format(time.DateOnly))))
		}
	}
	if err != nil {
		a.Error = err.Error()
		var fe *FetchError
		kind := FetchNetwork
		if errors.As(err, &fe) {
			kind = fe.Kind
		}
		url := PolicyURL(domain)
		switch kind {
		case FetchCertificate:
			add(findings.MTASTSCertificate.New("mta-sts."+domain, fmt.Sprintf("The certificate presented by mta-sts.%s is not valid: %v.", domain, err)))
		case FetchRedirect:
			add(findings.MTASTSRedirect.New(url, err.Error()+"."))
		case FetchTooLarge:
			add(findings.MTASTSPolicyTooLarge.New(url, err.Error()+"."))
		default:
			add(findings.MTASTSFetchFailed.New(url, fmt.Sprintf("The MTA-STS TXT record exists but the policy could not be fetched: %v. Senders cannot apply MTA-STS.", err)))
		}
		return a, nil
	}

	if !isTextPlain(resp.ContentType) {
		add(findings.MTASTSContentType.New(resp.URL, fmt.Sprintf("The policy is served as %q instead of text/plain.", resp.ContentType)))
	}
	pol, err := ParsePolicy(resp.Body)
	if err != nil {
		a.Error = err.Error()
		add(findings.MTASTSInvalidPolicy.New(resp.URL, fmt.Sprintf("The policy is invalid: %v.", err), truncate(resp.Body, 300)))
		return a, nil
	}
	a.Policy = pol
	if pol.LFOnly {
		add(findings.MTASTSLineEndings.New(resp.URL, "The policy uses LF line endings; RFC 8461 specifies CRLF. Most senders accept it."))
	}

	switch pol.Mode {
	case ModeTesting:
		add(findings.MTASTSTesting.New(domain, "The MTA-STS policy is in testing mode: failures are reported (TLS-RPT) but delivery is not blocked."))
	case ModeNone:
		add(findings.MTASTSModeNone.New(domain, "The MTA-STS policy mode is none, which disables MTA-STS protection."))
	}
	if pol.MaxAge < 86400 && pol.Mode != ModeNone {
		add(findings.MTASTSShortMaxAge.New(domain, fmt.Sprintf("max_age is %d seconds. Short lifetimes weaken protection against downgrade attacks between policy refreshes.", pol.MaxAge)))
	}

	var uncovered []string
	for _, h := range opts.MXHosts {
		if h == "." || h == "" {
			continue
		}
		if !pol.Covers(h) {
			uncovered = append(uncovered, h)
		}
	}
	if len(uncovered) > 0 && pol.Mode != ModeNone {
		f := findings.MTASTSMXMismatch.New(domain,
			fmt.Sprintf("MX hosts %s are not matched by the policy's mx patterns (%s).", strings.Join(uncovered, ", "), strings.Join(pol.MX, ", ")),
			uncovered...)
		if pol.Mode == ModeTesting {
			f = f.WithSeverity(findings.SeverityMedium)
		}
		add(f)
	}

	if findings.Max(a.Findings) <= findings.SeverityInfo && pol.Mode == ModeEnforce {
		add(findings.MTASTSValid.New(domain, fmt.Sprintf("MTA-STS is enforced (id %s, max_age %d).", rec.ID, pol.MaxAge)))
	}
	return a, nil
}
