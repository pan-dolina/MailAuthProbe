// Package tlsrpt assesses SMTP TLS Reporting (RFC 8460) records.
package tlsrpt

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

// Record is a parsed TLS-RPT record.
type Record struct {
	Raw string   `json:"raw"`
	RUA []string `json:"rua"`
	// InvalidURIs lists rua entries that are not valid mailto: or https:
	// URIs.
	InvalidURIs []string          `json:"invalid_uris,omitempty"`
	Extensions  map[string]string `json:"extensions,omitempty"`
}

// IsTLSRPT reports whether a TXT record claims to be a TLS-RPT record.
func IsTLSRPT(txt string) bool {
	v, _, _ := strings.Cut(txt, ";")
	return strings.TrimSpace(v) == "v=TLSRPTv1"
}

// Parse parses a TLS-RPT record (RFC 8460 section 3).
func Parse(txt string) (*Record, error) {
	if !IsTLSRPT(txt) {
		return nil, errors.New(`record must start with "v=TLSRPTv1;"`)
	}
	r := &Record{Raw: txt, Extensions: map[string]string{}}
	seen := map[string]bool{}
	for i, part := range strings.Split(txt, ";") {
		part = strings.Trim(part, " \t")
		if part == "" || i == 0 {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("malformed field %q", part)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		if name != "rua" {
			r.Extensions[name] = strings.TrimSpace(value)
			continue
		}
		for u := range strings.SplitSeq(value, ",") {
			u = strings.TrimSpace(u)
			if validURI(u) {
				r.RUA = append(r.RUA, u)
			} else {
				r.InvalidURIs = append(r.InvalidURIs, u)
			}
		}
	}
	if !seen["rua"] {
		return nil, errors.New("required field rua is missing")
	}
	return r, nil
}

func validURI(s string) bool {
	switch {
	case strings.HasPrefix(strings.ToLower(s), "mailto:"):
		addr, _, _ := strings.Cut(s[len("mailto:"):], "?")
		a, err := mail.ParseAddress(addr)
		return err == nil && a.Address == addr && strings.Contains(addr[strings.LastIndexByte(addr, '@')+1:], ".")
	case strings.HasPrefix(strings.ToLower(s), "https:"):
		u, err := url.Parse(s)
		return err == nil && u.Host != "" && u.User == nil
	}
	return false
}

// Assessment is the TLS-RPT part of a domain audit.
type Assessment struct {
	Name     string             `json:"name"`
	Records  []string           `json:"records,omitempty"`
	Record   *Record            `json:"record,omitempty"`
	Findings []findings.Finding `json:"-"`
}

// Assess audits the TLS-RPT record of domain. usesMTASTS indicates whether
// the domain deploys MTA-STS, which makes reporting more important.
func Assess(ctx context.Context, r dnsresolver.Resolver, domain string, usesMTASTS bool) (*Assessment, error) {
	domain = dnsresolver.Trim(domain)
	a := &Assessment{Name: "_smtp._tls." + domain}
	add := func(f findings.Finding) { a.Findings = append(a.Findings, f) }

	txts, err := r.LookupTXT(ctx, a.Name)
	if err != nil && !dnsresolver.IsNXDomain(err) {
		add(findings.DNSLookupFailed.New(a.Name, "The TLS-RPT lookup failed.", err.Error()))
		return a, err
	}
	for _, t := range txts {
		if IsTLSRPT(t) {
			a.Records = append(a.Records, t)
		}
	}
	switch len(a.Records) {
	case 0:
		f := findings.TLSRPTMissing.New(domain, fmt.Sprintf("%s does not request SMTP TLS reports, so TLS delivery failures to its MX hosts go unnoticed.", domain))
		if !usesMTASTS {
			f = f.WithSeverity(findings.SeverityInfo)
		}
		add(f)
		return a, nil
	case 1:
	default:
		add(findings.TLSRPTInvalid.New(a.Name, fmt.Sprintf("%s has %d TLS-RPT records; senders ignore all of them.", a.Name, len(a.Records)), a.Records...))
		return a, nil
	}
	rec, err := Parse(a.Records[0])
	if err != nil {
		add(findings.TLSRPTInvalid.New(a.Name, fmt.Sprintf("The TLS-RPT record is invalid: %v.", err), a.Records[0]))
		return a, nil
	}
	a.Record = rec
	if len(rec.InvalidURIs) > 0 {
		f := findings.TLSRPTInvalidURI.New(a.Name, "The TLS-RPT record contains report URIs that are not valid mailto: or https: URIs.", rec.InvalidURIs...)
		if len(rec.RUA) == 0 {
			f = f.WithSeverity(findings.SeverityHigh)
		}
		add(f)
	}
	if len(rec.RUA) > 0 && findings.Max(a.Findings) <= findings.SeverityInfo {
		add(findings.TLSRPTValid.New(a.Name, "TLS reports are sent to "+strings.Join(rec.RUA, ", ")+".", rec.Raw))
	}
	return a, nil
}
