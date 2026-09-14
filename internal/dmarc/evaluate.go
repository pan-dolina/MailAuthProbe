package dmarc

import (
	"context"
	"fmt"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
)

// DKIMInput is one verified DKIM signature.
type DKIMInput struct {
	Domain string
	Result string // "pass" counts; anything else does not
}

// MessageInput carries independently computed authentication results.
type MessageInput struct {
	// FromHeaders are the values of all From header fields.
	FromHeaders []string
	// SPFResult and SPFDomain describe the SPF identity used by DMARC
	// (MAIL FROM, or HELO for a null sender). SPFResult is empty when SPF
	// was not evaluated.
	SPFResult string
	SPFDomain string
	// SPFInferred is set when the SPF inputs were reconstructed from headers.
	SPFInferred bool
	DKIM        []DKIMInput
}

// Message DMARC results.
const (
	MessagePass      = "pass"
	MessageFail      = "fail"
	MessageNone      = "none"
	MessageTempError = "temperror"
	MessagePermError = "permerror"
	// MessageIndeterminate is not an RFC 7489 result: no aligned pass was
	// found, but SPF could not be evaluated or a DKIM signature could only be
	// partially verified, so a "fail" cannot be concluded.
	MessageIndeterminate = "indeterminate"
)

// MessageEvaluation is the DMARC outcome for a message.
type MessageEvaluation struct {
	Result     string     `json:"result"`
	Reason     string     `json:"reason"`
	FromDomain string     `json:"from_domain,omitempty"`
	Discovery  *Discovery `json:"discovery,omitempty"`
	// Policy is the policy that applies to the From domain (p or sp).
	Policy  Policy `json:"policy,omitempty"`
	Percent int    `json:"pct,omitempty"`
	// Disposition is the action requested for a failing message.
	Disposition       Policy `json:"disposition,omitempty"`
	SPFAligned        bool   `json:"spf_aligned"`
	DKIMAligned       bool   `json:"dkim_aligned"`
	AlignedDKIMDomain string `json:"aligned_dkim_domain,omitempty"`
	ADKIM             Mode   `json:"adkim,omitempty"`
	ASPF              Mode   `json:"aspf,omitempty"`

	Findings []findings.Finding `json:"-"`
}

// EvaluateMessage applies DMARC (RFC 7489 section 6.6) to a message.
func EvaluateMessage(ctx context.Context, r dnsresolver.Resolver, in MessageInput) *MessageEvaluation {
	ev := &MessageEvaluation{}
	add := func(f findings.Finding) { ev.Findings = append(ev.Findings, f) }

	from, problem := authorDomain(in.FromHeaders)
	if problem != "" {
		ev.Result, ev.Reason = MessagePermError, problem
		add(findings.DMARCMessageBadFrom.New("", problem+" DMARC cannot be applied reliably; receivers commonly reject such messages.", in.FromHeaders...))
		return ev
	}
	ev.FromDomain = from

	disc, err := Discover(ctx, r, from)
	ev.Discovery = disc
	if err != nil {
		ev.Result, ev.Reason = MessageTempError, err.Error()
		add(findings.DMARCMessageTempError.New(from, "DMARC policy discovery failed; receivers would return temperror.", err.Error()))
		return ev
	}
	rec := disc.Policy()
	if rec == nil {
		ev.Result = MessageNone
		switch {
		case len(disc.Records) == 0:
			ev.Reason = "no DMARC policy is published for " + from
		case len(disc.Records) > 1:
			ev.Reason = "multiple DMARC records are published for " + disc.PolicyDomain
		default:
			ev.Reason = fmt.Sprintf("the DMARC record of %s is invalid: %v", disc.PolicyDomain, disc.ParseErr)
		}
		add(findings.DMARCMessageNoPolicy.New(from, fmt.Sprintf("The message is not protected by DMARC: %s.", ev.Reason)))
		return ev
	}
	ev.ADKIM, ev.ASPF, ev.Percent = rec.ADKIM, rec.ASPF, rec.Percent
	ev.Policy = rec.Policy
	if disc.Inherited {
		ev.Policy = rec.EffectiveSubdomainPolicy()
	}

	// Identifier alignment.
	spfPass := in.SPFResult == "pass"
	if spfPass {
		ev.SPFAligned = Aligned(in.SPFDomain, from, rec.ASPF)
	}
	var passingDKIM []string
	for _, d := range in.DKIM {
		if d.Result != "pass" {
			continue
		}
		passingDKIM = append(passingDKIM, d.Domain)
		if !ev.DKIMAligned && Aligned(d.Domain, from, rec.ADKIM) {
			ev.DKIMAligned = true
			ev.AlignedDKIMDomain = strings.ToLower(d.Domain)
		}
	}

	evidence := []string{
		"header.from=" + from,
		"policy_domain=" + disc.PolicyDomain,
		fmt.Sprintf("p=%s sp=%s pct=%d adkim=%s aspf=%s", rec.Policy, rec.EffectiveSubdomainPolicy(), rec.Percent, rec.ADKIM, rec.ASPF),
		fmt.Sprintf("spf=%s domain=%s aligned=%v", orNone(in.SPFResult), orNone(in.SPFDomain), ev.SPFAligned),
	}
	for _, d := range in.DKIM {
		evidence = append(evidence, fmt.Sprintf("dkim=%s d=%s aligned=%v", d.Result, d.Domain, d.Result == "pass" && Aligned(d.Domain, from, rec.ADKIM)))
	}

	if ev.SPFAligned || ev.DKIMAligned {
		if !ev.DKIMAligned && in.SPFInferred {
			evidence = append(evidence, "note: the aligned SPF pass relies on SMTP inputs inferred from message headers")
		}
		ev.Result = MessagePass
		var via []string
		if ev.DKIMAligned {
			via = append(via, "DKIM (d="+ev.AlignedDKIMDomain+")")
		}
		if ev.SPFAligned {
			via = append(via, "SPF ("+in.SPFDomain+")")
		}
		ev.Reason = "aligned " + strings.Join(via, " and ")
		add(findings.DMARCMessagePass.New(from, fmt.Sprintf("DMARC pass for %s via %s.", from, strings.Join(via, " and ")), evidence...))
		return ev
	}

	// Without an aligned pass, fail only if every input produced a definite
	// result (RFC 7489 section 6.6.2).
	var temp, incomplete []string
	switch in.SPFResult {
	case "temperror":
		temp = append(temp, "SPF temperror")
	case "":
		incomplete = append(incomplete, "SPF was not evaluated")
	}
	for _, d := range in.DKIM {
		switch d.Result {
		case "temperror":
			temp = append(temp, "DKIM temperror for d="+d.Domain)
		case "neutral":
			incomplete = append(incomplete, "DKIM signature by d="+d.Domain+" could not be fully verified")
		}
	}
	switch {
	case len(temp) > 0:
		ev.Result = MessageTempError
		ev.Reason = "no aligned pass and " + strings.Join(temp, ", ")
		add(findings.DMARCMessageTempError.New(from, fmt.Sprintf("DMARC for %s cannot be decided: %s. Receivers would return temperror.", from, strings.Join(temp, ", ")), evidence...))
		return ev
	case len(incomplete) > 0:
		ev.Result = MessageIndeterminate
		ev.Reason = "no aligned pass, but " + strings.Join(incomplete, "; ")
		add(findings.DMARCMessageIndeterminate.New(from, fmt.Sprintf("No aligned SPF or DKIM pass was found for %s, but the evaluation is incomplete: %s. The message may still pass DMARC at the receiver.", from, strings.Join(incomplete, "; ")), evidence...))
		return ev
	}

	ev.Result = MessageFail
	ev.Disposition = ev.Policy
	ev.Reason = "no authenticated identifier is aligned with " + from
	desc := fmt.Sprintf("DMARC fail for %s: neither SPF nor DKIM produced an aligned pass. The domain requests p=%s", from, ev.Policy)
	if rec.Percent < 100 {
		desc += fmt.Sprintf(" for %d%% of failing messages", rec.Percent)
	}
	desc += "."
	f := findings.DMARCMessageFail.New(from, desc, evidence...)
	if ev.Policy == PolicyNone {
		f = f.WithSeverity(findings.SeverityMedium)
	}
	add(f)

	// Explain near misses: identifiers that authenticated but did not align.
	if spfPass && !Aligned(in.SPFDomain, from, rec.ASPF) {
		if rec.ASPF == ModeStrict && Aligned(in.SPFDomain, from, ModeRelaxed) {
			add(findings.DMARCMessageStrictMisalign.New(from, fmt.Sprintf("SPF passed for %s, which is in the same organization as %s, but aspf=s requires an exact match.", in.SPFDomain, from)))
		} else {
			add(findings.DMARCMessageSPFUnaligned.New(from, fmt.Sprintf("SPF passed for %s, which is not aligned with %s.", in.SPFDomain, from)))
		}
	}
	for _, d := range passingDKIM {
		if rec.ADKIM == ModeStrict && Aligned(d, from, ModeRelaxed) {
			add(findings.DMARCMessageStrictMisalign.New(from, fmt.Sprintf("DKIM passed for d=%s, which is in the same organization as %s, but adkim=s requires an exact match.", d, from)))
		} else {
			add(findings.DMARCMessageDKIMUnaligned.New(from, fmt.Sprintf("DKIM passed for d=%s, which is not aligned with %s.", d, from)))
		}
	}
	return ev
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// authorDomain extracts the RFC5322.From domain. DMARC requires exactly one
// From field containing exactly one mailbox (RFC 7489 section 6.6.1).
func authorDomain(fromHeaders []string) (string, string) {
	switch len(fromHeaders) {
	case 0:
		return "", "The message has no From header."
	case 1:
	default:
		return "", fmt.Sprintf("The message has %d From headers.", len(fromHeaders))
	}
	list, err := mailparser.ParseAddressList(fromHeaders[0])
	if err != nil {
		return "", fmt.Sprintf("The From header cannot be parsed: %v.", err)
	}
	if len(list) != 1 {
		return "", fmt.Sprintf("The From header contains %d mailboxes.", len(list))
	}
	d := list[0].Domain
	if d == "" || !validDomain(d) {
		return "", fmt.Sprintf("The From address %q has no valid domain.", list[0].Address)
	}
	return d, ""
}
