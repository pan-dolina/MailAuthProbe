package spf

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

// Input provenance.
const (
	SourceFlag        = "flag"
	SourceReceived    = "received"
	SourceReceivedSPF = "received-spf"
	SourceReturnPath  = "return-path"
)

// Input is an SMTP session value with its provenance.
type Input struct {
	Value  string `json:"value"`
	Source string `json:"source"`
	// Inferred is true for values reconstructed from message headers rather
	// than supplied by the operator.
	Inferred bool `json:"inferred"`
}

// MessageInputs are the SMTP session parameters SPF needs.
type MessageInputs struct {
	IP       *Input `json:"ip,omitempty"`
	HELO     *Input `json:"helo,omitempty"`
	MailFrom *Input `json:"mail_from,omitempty"`
	// NullSender is set when MAIL FROM was known to be empty ("<>").
	NullSender bool `json:"null_sender,omitempty"`
}

// MessageCheck is the SPF outcome for a message.
type MessageCheck struct {
	Inputs   MessageInputs `json:"inputs"`
	MailFrom *Evaluation   `json:"mail_from,omitempty"`
	HELO     *Evaluation   `json:"helo,omitempty"`
	// Result is the result for the identity used by DMARC: MAIL FROM, or
	// HELO for a null sender. Empty when SPF could not be evaluated.
	Result Result `json:"result,omitempty"`
	// Domain is the domain whose SPF result is Result.
	Domain   string             `json:"domain,omitempty"`
	Findings []findings.Finding `json:"-"`
}

// CheckMessage evaluates SPF for the MAIL FROM and HELO identities.
func (c *Checker) CheckMessage(ctx context.Context, in MessageInputs) *MessageCheck {
	mc := &MessageCheck{Inputs: in}
	add := func(f findings.Finding) { mc.Findings = append(mc.Findings, f) }

	if in.IP == nil {
		add(findings.SPFNotEvaluated.New("", "SPF was not evaluated: the client IP address is unknown. Pass --source-ip (and --helo, --mail-from) or analyse a message with Received headers."))
		return mc
	}
	ip, err := netip.ParseAddr(in.IP.Value)
	if err != nil {
		add(findings.SPFNotEvaluated.New("", fmt.Sprintf("SPF was not evaluated: %q is not a valid IP address.", in.IP.Value)))
		return mc
	}
	if in.MailFrom == nil && in.HELO == nil && !in.NullSender {
		add(findings.SPFNotEvaluated.New("", "SPF was not evaluated: neither MAIL FROM nor HELO is known. Pass --mail-from or --helo."))
		return mc
	}

	var inferred []string
	for name, v := range map[string]*Input{"client IP": in.IP, "HELO": in.HELO, "MAIL FROM": in.MailFrom} {
		if v != nil && v.Inferred {
			inferred = append(inferred, fmt.Sprintf("%s %s (from %s)", name, v.Value, v.Source))
		}
	}
	if len(inferred) > 0 {
		slices.Sort(inferred)
		add(findings.SPFInputsInferred.New("", "SPF inputs were reconstructed from message headers, which the sender can forge above the receiving organization's boundary. Confirm them with --source-ip, --helo and --mail-from from the receiving MTA's logs.", inferred...))
	}

	helo := ""
	if in.HELO != nil {
		helo = dnsresolver.Trim(in.HELO.Value)
		mc.HELO = c.CheckHost(ctx, Request{IP: ip, HELO: helo, Domain: helo, Sender: "postmaster@" + helo})
	}
	if in.MailFrom != nil && !in.NullSender {
		mc.MailFrom = c.CheckHost(ctx, Request{IP: ip, Sender: in.MailFrom.Value, HELO: helo})
		mc.Result, mc.Domain = mc.MailFrom.Result, mc.MailFrom.Domain
	} else if mc.HELO != nil {
		mc.Result, mc.Domain = mc.HELO.Result, mc.HELO.Domain
	}
	if mc.Result == "" {
		add(findings.SPFNotEvaluated.New("", "SPF was not evaluated: the sender was null and no HELO name is known."))
		return mc
	}

	ev := mc.MailFrom
	identity := "MAIL FROM"
	if ev == nil {
		ev, identity = mc.HELO, "HELO"
	}
	evidence := []string{"client-ip=" + ip.String(), "identity=" + strings.ToLower(strings.ReplaceAll(identity, " ", "")), "domain=" + mc.Domain}
	if ev.MatchedTerm != "" {
		evidence = append(evidence, "matched="+ev.MatchedTerm+" in "+ev.MatchedDomain)
	}
	desc := fmt.Sprintf("SPF for %s %s from %s: %s. %s.", identity, mc.Domain, ip, mc.Result, ev.Reason)
	switch mc.Result {
	case ResultPass:
		add(findings.SPFMessagePass.New(mc.Domain, desc, evidence...))
	case ResultFail:
		add(findings.SPFMessageFail.New(mc.Domain, desc, evidence...))
	case ResultSoftFail:
		add(findings.SPFMessageSoftFail.New(mc.Domain, desc, evidence...))
	case ResultNeutral, ResultNone:
		add(findings.SPFMessageNeutral.New(mc.Domain, desc, evidence...))
	case ResultTempError, ResultPermError:
		f := findings.SPFMessageError.New(mc.Domain, desc, evidence...)
		if ev.LoopDetected || ev.LookupLimitExceeded {
			f = f.WithSeverity(findings.SeverityHigh)
		}
		add(f)
	}
	return mc
}
