package dmarc

import (
	"context"
	"fmt"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

// Assessment is the result of a DMARC domain audit.
type Assessment struct {
	Discovery *Discovery         `json:"discovery"`
	Findings  []findings.Finding `json:"-"`
}

// Assess discovers and validates the DMARC policy of domain. The returned
// error is non-nil only for DNS failures that prevented discovery.
func Assess(ctx context.Context, r dnsresolver.Resolver, domain string) (*Assessment, error) {
	disc, err := Discover(ctx, r, domain)
	a := &Assessment{Discovery: disc}
	add := func(f findings.Finding) { a.Findings = append(a.Findings, f) }
	subject := disc.Domain

	if err != nil {
		add(findings.DNSLookupFailed.New(subject, "DMARC policy discovery failed.", err.Error()))
		return a, err
	}
	switch {
	case len(disc.Records) == 0:
		desc := fmt.Sprintf("No DMARC record was found at _dmarc.%s", disc.Domain)
		if disc.OrgDomain != disc.Domain {
			desc += fmt.Sprintf(" or at the organizational domain _dmarc.%s", disc.OrgDomain)
		}
		add(findings.DMARCMissing.New(subject, desc+". Receivers apply no DMARC policy, so the domain can be spoofed in the From header."))
		return a, nil
	case len(disc.Records) > 1:
		add(findings.DMARCMultiple.New(subject, fmt.Sprintf("_dmarc.%s publishes %d DMARC records.", disc.PolicyDomain, len(disc.Records)), disc.Records...))
		return a, nil
	case disc.ParseErr != nil:
		add(findings.DMARCInvalid.New(subject, fmt.Sprintf("The DMARC record at _dmarc.%s cannot be used: %v.", disc.PolicyDomain, disc.ParseErr), disc.Records[0]))
		return a, nil
	}

	rec := disc.Record
	if disc.Inherited {
		add(findings.DMARCInherited.New(subject, fmt.Sprintf("%s has no DMARC record of its own; the policy of %s applies (sp=%s).", disc.Domain, disc.PolicyDomain, rec.EffectiveSubdomainPolicy())))
	}
	if rec.PolicyImplied {
		add(findings.DMARCInvalid.New(subject, "The DMARC record has no valid p tag. Because it lists a valid rua, receivers treat it as p=none.", rec.Raw).WithSeverity(findings.SeverityMedium))
	}

	for _, is := range rec.Issues {
		ev := []string{rec.Raw}
		switch is.Kind {
		case IssueInvalidValue:
			add(findings.DMARCInvalidValue.New(subject, is.Msg+".", ev...))
		case IssueDuplicateTag:
			add(findings.DMARCDuplicateTag.New(subject, is.Msg+".", ev...))
		case IssueUnknownTag:
			add(findings.DMARCUnknownTag.New(subject, is.Msg+".", ev...))
		case IssueInvalidURI:
			add(findings.DMARCInvalidURI.New(subject, is.Msg+".", ev...))
		}
	}

	// The policy that applies to the audited domain itself.
	effective := rec.Policy
	if disc.Inherited {
		effective = rec.EffectiveSubdomainPolicy()
	}
	switch effective {
	case PolicyNone:
		add(findings.DMARCPolicyNone.New(subject, fmt.Sprintf("The DMARC policy for %s is none: receivers report but do not act on failing mail.", disc.Domain), rec.Raw))
	case PolicyQuarantine:
		add(findings.DMARCPolicyQuarantine.New(subject, fmt.Sprintf("The DMARC policy for %s is quarantine.", disc.Domain), rec.Raw))
	}
	if rec.Percent < 100 && effective != PolicyNone {
		sev := findings.SeverityMedium
		if rec.Percent == 0 {
			sev = findings.SeverityHigh
		}
		add(findings.DMARCPartialPct.New(subject, fmt.Sprintf("pct=%d: the %s policy is applied to %d%% of failing messages.", rec.Percent, effective, rec.Percent), rec.Raw).WithSeverity(sev))
	}
	if !disc.Inherited && rec.SubdomainPolicy != "" && rec.SubdomainPolicy.Strength() < rec.Policy.Strength() {
		add(findings.DMARCWeakSubdomainPolicy.New(subject, fmt.Sprintf("p=%s but sp=%s: subdomains of %s are less protected than the domain itself.", rec.Policy, rec.SubdomainPolicy, disc.PolicyDomain), rec.Raw))
	}
	if len(rec.RUA) == 0 {
		add(findings.DMARCNoRUA.New(subject, "The DMARC record does not request aggregate reports (rua).", rec.Raw))
	}
	if len(rec.RUF) > 0 {
		add(findings.DMARCRUF.New(subject, "Failure reports may contain message content and personal data; many receivers never send them.", rec.Raw))
	} else if rec.HasTag("fo") {
		add(findings.DMARCFONoRUF.New(subject, "The fo tag only controls failure reports, but no ruf destination is published.", rec.Raw))
	}
	if rec.ADKIM == ModeStrict || rec.ASPF == ModeStrict {
		add(findings.DMARCStrictAlignment.New(subject, fmt.Sprintf("adkim=%s, aspf=%s: mail signed or sent from subdomains of %s will not align.", rec.ADKIM, rec.ASPF, disc.PolicyDomain), rec.Raw))
	}

	if err := checkExternalDestinations(ctx, r, disc.PolicyDomain, rec, add); err != nil {
		return a, err
	}

	if findings.Max(a.Findings) <= findings.SeverityInfo && effective == PolicyReject {
		add(findings.DMARCEnforced.New(subject, fmt.Sprintf("DMARC is enforced for %s with p=reject.", disc.Domain), rec.Raw))
	}
	return a, nil
}

// checkExternalDestinations verifies that report destinations outside the
// policy domain's organization have authorized the policy domain
// (RFC 7489 section 7.1).
func checkExternalDestinations(ctx context.Context, r dnsresolver.Resolver, policyDomain string, rec *Record, add func(findings.Finding)) error {
	org := OrganizationalDomain(policyDomain)
	checked := map[string]bool{}
	var infraErr error
	for _, u := range append(append([]ReportURI{}, rec.RUA...), rec.RUF...) {
		if u.Scheme != "mailto" || u.Domain == "" || OrganizationalDomain(u.Domain) == org || checked[u.Domain] {
			continue
		}
		checked[u.Domain] = true
		name := policyDomain + "._report._dmarc." + u.Domain
		txts, err := r.LookupTXT(ctx, name)
		if err != nil && !dnsresolver.IsNXDomain(err) {
			add(findings.DNSLookupFailed.New(u.Domain, fmt.Sprintf("Could not verify authorization of external report destination %s.", u.URI), err.Error()))
			if dnsresolver.IsInfrastructure(err) {
				infraErr = err
			}
			continue
		}
		authorized := false
		for _, t := range txts {
			if strings.HasPrefix(strings.TrimSpace(t), "v=DMARC1") {
				authorized = true
			}
		}
		if !authorized {
			add(findings.DMARCExternalUnauthorized.New(u.Domain,
				fmt.Sprintf("Reports for %s are sent to %s, but %s does not publish an authorization record.", policyDomain, u.URI, u.Domain),
				"expected TXT at "+name))
		}
	}
	return infraErr
}
