package analyzer

import (
	"context"
	"sync"

	"github.com/marcindolinski/mailauthprobe/internal/dkim"
	"github.com/marcindolinski/mailauthprobe/internal/dmarc"
	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/mtasts"
	"github.com/marcindolinski/mailauthprobe/internal/mx"
	"github.com/marcindolinski/mailauthprobe/internal/report"
	"github.com/marcindolinski/mailauthprobe/internal/spf"
	"github.com/marcindolinski/mailauthprobe/internal/tlsrpt"
)

// Domain audits the mail configuration of domain.
func Domain(ctx context.Context, domain string, opts Options) *report.Report {
	domain = dnsresolver.Trim(domain)
	s := newSession(opts, report.KindDomain, domain)
	d := &report.Domain{Name: domain}
	s.rep.Domain = d

	// MX, SPF, DMARC and DKIM are independent; run them concurrently and
	// merge results in a fixed order.
	var (
		wg                             sync.WaitGroup
		mxErr, spfErr, dmarcErr, dkErr error
	)
	wg.Add(4)
	go func() { defer wg.Done(); d.MX, mxErr = mx.Assess(ctx, s.resolver, domain) }()
	go func() {
		defer wg.Done()
		d.SPF, spfErr = (&spf.Analyzer{Resolver: s.resolver}).Analyze(ctx, domain)
	}()
	go func() { defer wg.Done(); d.DMARC, dmarcErr = dmarc.Assess(ctx, s.resolver, domain) }()
	go func() { defer wg.Done(); d.DKIM, dkErr = dkim.Assess(ctx, s.resolver, domain, s.opts.DKIMSelectors) }()
	wg.Wait()

	s.add(d.MX.Findings...)
	s.add(d.SPF.Findings...)
	s.add(d.DMARC.Findings...)
	s.add(d.DKIM.Findings...)
	s.dnsError("mx", mxErr)
	s.dnsError("spf", spfErr)
	s.dnsError("dmarc", dmarcErr)
	s.dnsError("dkim", dkErr)

	var mxHosts []string
	for _, h := range d.MX.Hosts {
		mxHosts = append(mxHosts, h.Name)
	}
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
