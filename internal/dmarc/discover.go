package dmarc

import (
	"context"
	"fmt"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
)

// Discovery is the outcome of DMARC policy discovery for a domain.
type Discovery struct {
	// Domain is the domain whose policy was requested.
	Domain string `json:"domain"`
	// OrgDomain is its organizational domain.
	OrgDomain string `json:"organizational_domain"`
	// PolicyDomain is where the record was found (Domain or OrgDomain).
	PolicyDomain string `json:"policy_domain,omitempty"`
	// Records are the DMARC TXT records found at PolicyDomain, or at the
	// last name queried when none were found.
	Records []string `json:"records,omitempty"`
	Record  *Record  `json:"record,omitempty"`
	// ParseErr is set when a single record was found but is unusable.
	ParseErr error `json:"-"`
	// ParseError mirrors ParseErr for machine-readable output.
	ParseError string `json:"parse_error,omitempty"`
	// Inherited is set when the policy comes from the organizational domain.
	Inherited bool `json:"inherited,omitempty"`
}

// Discover performs DMARC policy discovery (RFC 7489 section 6.6.3). The
// returned error is non-nil only for lookup failures, which correspond to
// the DMARC "temperror" result.
func Discover(ctx context.Context, r dnsresolver.Resolver, domain string) (*Discovery, error) {
	d := &Discovery{Domain: normalize(domain), OrgDomain: OrganizationalDomain(domain)}

	found, err := d.try(ctx, r, d.Domain)
	if err != nil || found {
		return d, err
	}
	if d.OrgDomain == d.Domain || d.OrgDomain == "" {
		return d, nil
	}
	found, err = d.try(ctx, r, d.OrgDomain)
	if found {
		d.Inherited = true
	}
	return d, err
}

// try queries _dmarc.<name> and reports whether discovery should stop there,
// i.e. whether at least one DMARC record exists at that name.
func (d *Discovery) try(ctx context.Context, r dnsresolver.Resolver, name string) (bool, error) {
	txts, err := r.LookupTXT(ctx, "_dmarc."+name)
	if err != nil && !dnsresolver.IsNXDomain(err) {
		return false, fmt.Errorf("DMARC lookup for %s: %w", name, err)
	}
	var records []string
	for _, t := range txts {
		if IsDMARC(t) {
			records = append(records, t)
		}
	}
	if len(records) == 0 {
		return false, nil
	}
	d.PolicyDomain = name
	d.Records = records
	if len(records) == 1 {
		d.Record, d.ParseErr = Parse(records[0])
		if d.ParseErr != nil {
			d.ParseError = d.ParseErr.Error()
		}
	}
	return true, nil
}

// Policy returns the usable record, or nil when discovery found none, found
// several, or found an invalid one; in all those cases DMARC is not applied.
func (d *Discovery) Policy() *Record {
	if len(d.Records) != 1 || d.ParseErr != nil {
		return nil
	}
	return d.Record
}
