// Package analyzer orchestrates domain and message assessments and
// assembles their results into a report.
package analyzer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver"
	"github.com/pan-dolina/mailauthprobe/internal/findings"
	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
	"github.com/pan-dolina/mailauthprobe/internal/mtasts"
	"github.com/pan-dolina/mailauthprobe/internal/report"
	"github.com/pan-dolina/mailauthprobe/internal/version"
)

// DefaultQueryBudget is the maximum number of DNS queries per scan.
const DefaultQueryBudget = 250

// Options configure an analysis.
type Options struct {
	// Resolver is the underlying resolver; the analyzer adds a query budget
	// and a cache on top of it.
	Resolver dnsresolver.Resolver
	// QueryBudget overrides DefaultQueryBudget.
	QueryBudget int
	// Fetcher retrieves MTA-STS policies. Nil means the default HTTPS
	// fetcher using Resolver.
	Fetcher mtasts.Fetcher
	// HTTPTimeout bounds the MTA-STS policy fetch.
	HTTPTimeout time.Duration

	// DKIMSelectors are audited during domain scans.
	DKIMSelectors []string

	// SourceIP, HELO and MailFrom override values inferred from headers
	// during message analysis.
	SourceIP string
	HELO     string
	MailFrom string

	// Limits for message parsing.
	Limits mailparser.Limits
	// Now is the evaluation time; zero means time.Now().
	Now time.Time
}

type session struct {
	opts     Options
	budget   *dnsresolver.Budget
	resolver dnsresolver.Resolver
	rep      *report.Report
}

func newSession(opts Options, kind, target string) *session {
	if opts.QueryBudget <= 0 {
		opts.QueryBudget = DefaultQueryBudget
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	budget := dnsresolver.WithBudget(opts.Resolver, opts.QueryBudget)
	return &session{
		opts:     opts,
		budget:   budget,
		resolver: dnsresolver.NewCache(budget),
		rep: &report.Report{
			SchemaVersion: report.SchemaVersion,
			Tool:          report.Tool{Name: "mailauthprobe", Version: version.Get().Version},
			Kind:          kind,
			Target:        target,
		},
	}
}

func (s *session) add(fs ...findings.Finding) {
	s.rep.Findings = append(s.rep.Findings, fs...)
}

// dnsError records a DNS failure that made a component's result unreliable.
// Budget exhaustion is reported once as a finding instead.
func (s *session) dnsError(component string, err error) {
	if err == nil {
		return
	}
	if dnsresolver.KindOf(err) == dnsresolver.KindBudget {
		return
	}
	if dnsresolver.IsInfrastructure(err) {
		s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorDNS, Component: component, Message: err.Error()})
	}
}

func (s *session) finish(ctx context.Context) *report.Report {
	if s.budget.Exhausted() {
		// Individual lookups rejected by the budget are summarised in one
		// finding instead of one "lookup failed" finding each.
		var kept []findings.Finding
		var affected []string
		for _, f := range s.rep.Findings {
			if f.ID == findings.DNSLookupFailed.ID && slices.ContainsFunc(f.Evidence, isBudgetEvidence) {
				affected = append(affected, f.Subject)
				continue
			}
			kept = append(kept, f)
		}
		s.rep.Findings = kept
		slices.Sort(affected)
		s.add(findings.DNSQueryBudgetExceeded.New("", fmt.Sprintf("The scan reached its limit of %d DNS queries; some checks are incomplete.", s.opts.QueryBudget), slices.Compact(affected)...))
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorDNS, Component: "scan", Message: "scan deadline exceeded: results are incomplete"})
	case ctx.Err() != nil:
		s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorDNS, Component: "scan", Message: "scan interrupted: results are incomplete"})
	}
	s.rep.Finalize(s.budget.Sent())
	return s.rep
}

func isBudgetEvidence(ev string) bool {
	return strings.Contains(ev, dnsresolver.KindBudget.String())
}
