package analyzer

import (
	"context"
	"strings"

	"github.com/pan-dolina/mailauthprobe/internal/dkim"
	"github.com/pan-dolina/mailauthprobe/internal/dmarc"
	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver"
	"github.com/pan-dolina/mailauthprobe/internal/mailprovider"
	"github.com/pan-dolina/mailauthprobe/internal/mtasts"
	"github.com/pan-dolina/mailauthprobe/internal/mx"
	"github.com/pan-dolina/mailauthprobe/internal/report"
	"github.com/pan-dolina/mailauthprobe/internal/spf"
	"github.com/pan-dolina/mailauthprobe/internal/tlsrpt"
)

// Domain audits the mail configuration of domain.
func Domain(ctx context.Context, domain string, opts Options) *report.Report {
	domain = dnsresolver.Trim(domain)
	s := newSession(opts, report.KindDomain, domain)
	d := &report.Domain{Name: domain}
	s.rep.Domain = d

	// Checks run sequentially. Running them concurrently saves little
	// (answers are cached and most scans need a few dozen queries) but makes
	// the order in which checks consume the shared query budget, and
	// therefore the report, depend on scheduling.
	var mxErr, spfErr, dmarcErr, dkErr error
	d.MX, mxErr = mx.Assess(ctx, s.resolver, domain)
	d.SPF, spfErr = (&spf.Analyzer{Resolver: dnsresolver.WithBudget(s.resolver, spfQueryBudget)}).Analyze(ctx, domain)
	d.DMARC, dmarcErr = dmarc.Assess(ctx, s.resolver, domain)
	var mxHosts []string
	for _, h := range d.MX.Hosts {
		mxHosts = append(mxHosts, h.Name)
	}
	providers := mailprovider.Detect(mxHosts, spfTargets(d.SPF, domain))
	d.DKIM, dkErr = dkim.Assess(ctx, s.resolver, domain, s.opts.DKIMSelectors, providers)

	s.add(d.MX.Findings...)
	s.add(d.SPF.Findings...)
	s.add(d.DMARC.Findings...)
	s.add(d.DKIM.Findings...)
	s.dnsError("mx", mxErr)
	s.dnsError("spf", spfErr)
	s.dnsError("dmarc", dmarcErr)
	s.dnsError("dkim", dkErr)

	fetcher := s.opts.Fetcher
	if fetcher == nil {
		fetcher = &mtasts.HTTPFetcher{Resolver: s.resolver, Timeout: s.opts.HTTPTimeout}
	}
	var err error
	if !d.MX.NullMX {
		d.MTASTS, err = mtasts.Assess(ctx, domain, mtasts.Options{Resolver: s.resolver, Fetcher: fetcher, MXHosts: mxHosts, Now: s.opts.Now})
		s.add(d.MTASTS.Findings...)
		s.dnsError("mta-sts", err)
	}
	usesSTS := d.MTASTS != nil && d.MTASTS.Record != nil
	d.TLSRPT, err = tlsrpt.Assess(ctx, s.resolver, domain, usesSTS)
	s.add(d.TLSRPT.Findings...)
	s.dnsError("tls-rpt", err)

	return s.finish(ctx)
}

// spfTargets returns the include and redirect targets that the SPF policy of
// domain delegates to. Records of the domain and its subdomains are followed;
// records of other domains are listed but not descended into, so that a
// provider's own includes do not make its sub-processors look like providers
// of the audited domain.
func spfTargets(a *spf.Analysis, domain string) []string {
	var out []string
	var walk func(n *spf.Node)
	walk = func(n *spf.Node) {
		for _, c := range n.Children {
			out = append(out, c.Domain)
			if inDomain(c.Domain, domain) {
				walk(c)
			}
		}
	}
	if a != nil && a.Tree != nil {
		walk(a.Tree)
	}
	return out
}

func inDomain(name, domain string) bool {
	name = strings.ToLower(dnsresolver.Trim(name))
	domain = strings.ToLower(dnsresolver.Trim(domain))
	return name == domain || strings.HasSuffix(name, "."+domain)
}
