package spf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
)

// Limits bound the work done while evaluating SPF.
type Limits struct {
	// MaxLookups is the limit on DNS-querying terms (RFC 7208: 10).
	MaxLookups int
	// MaxVoidLookups is the limit on lookups returning no data (RFC 7208
	// recommends 2).
	MaxVoidLookups int
	// MaxMXNames and MaxPTRNames limit the names considered by "mx" and
	// "ptr" (RFC 7208: 10).
	MaxMXNames  int
	MaxPTRNames int
	// MaxDepth is a safety net on include/redirect nesting, independent of
	// MaxLookups.
	MaxDepth int
}

// DefaultLimits are the limits mandated or recommended by RFC 7208.
var DefaultLimits = Limits{MaxLookups: 10, MaxVoidLookups: 2, MaxMXNames: 10, MaxPTRNames: 10, MaxDepth: 16}

// Request is the input to check_host().
type Request struct {
	// IP is the SMTP client address.
	IP netip.Addr
	// Sender is the MAIL FROM address. When empty, "postmaster@" + HELO is
	// used (RFC 7208 section 2.4).
	Sender string
	// HELO is the HELO/EHLO identity.
	HELO string
	// Domain is the initial <domain>; when empty it is derived from Sender.
	Domain string
	// Receiver is the receiving host name for the "r" macro.
	Receiver string
	// Now is used for the "t" macro; zero means time.Now().
	Now time.Time
}

// Step is one entry in the evaluation trace.
type Step struct {
	Depth  int    `json:"depth"`
	Domain string `json:"domain"`
	Term   string `json:"term,omitempty"`
	Note   string `json:"note"`
}

// Evaluation is the outcome of check_host().
type Evaluation struct {
	Result Result `json:"result"`
	// Reason explains how the result was reached.
	Reason string `json:"reason"`
	// Domain is the initial domain that was checked.
	Domain string `json:"domain"`
	// MatchedTerm and MatchedDomain identify the directive that decided the
	// result, if any.
	MatchedTerm   string `json:"matched_term,omitempty"`
	MatchedDomain string `json:"matched_domain,omitempty"`
	// Explanation is the expanded "exp" text for fail results.
	Explanation string `json:"explanation,omitempty"`
	Lookups     int    `json:"dns_lookups"`
	VoidLookups int    `json:"void_lookups"`
	Trace       []Step `json:"trace"`
	// LoopDetected is set when an include or redirect chain revisited a
	// domain.
	LoopDetected bool `json:"loop_detected,omitempty"`
	// LookupLimitExceeded is set when the result is permerror due to limits.
	LookupLimitExceeded bool `json:"lookup_limit_exceeded,omitempty"`
}

// Checker evaluates SPF policies.
type Checker struct {
	Resolver dnsresolver.Resolver
	Limits   Limits
}

// errPerm and errTemp carry an early termination reason through recursion.
type evalError struct {
	result Result
	reason string
}

func (e *evalError) Error() string { return string(e.result) + ": " + e.reason }

func permErr(format string, args ...any) error {
	return &evalError{result: ResultPermError, reason: fmt.Sprintf(format, args...)}
}

func tempErr(format string, args ...any) error {
	return &evalError{result: ResultTempError, reason: fmt.Sprintf(format, args...)}
}

type evaluator struct {
	resolver dnsresolver.Resolver
	limits   Limits
	req      Request
	ev       *Evaluation
	stack    []string
	pCache   map[string]string
}

// CheckHost evaluates the SPF policy for req (RFC 7208 section 4).
func (c *Checker) CheckHost(ctx context.Context, req Request) *Evaluation {
	limits := c.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits
	}
	if req.Now.IsZero() {
		req.Now = time.Now()
	}
	req.IP = req.IP.Unmap()
	if req.Sender == "" && req.HELO != "" {
		req.Sender = "postmaster@" + req.HELO
	} else if strings.HasPrefix(req.Sender, "@") || !strings.Contains(req.Sender, "@") && req.Sender != "" {
		local, domain := splitSender(req.Sender)
		req.Sender = local + "@" + domain
	}
	if req.Domain == "" {
		_, req.Domain = splitSender(req.Sender)
	}
	req.Domain = dnsresolver.Trim(req.Domain)

	e := &evaluator{resolver: c.Resolver, limits: limits, req: req, ev: &Evaluation{Domain: req.Domain, Trace: []Step{}}, pCache: map[string]string{}}
	result, err := e.checkHost(ctx, req.Domain, 0)
	var ee *evalError
	if errors.As(err, &ee) {
		e.ev.Result = ee.result
		e.ev.Reason = ee.reason
	} else {
		e.ev.Result = result
	}
	return e.ev
}

func (e *evaluator) trace(depth int, domain, term, format string, args ...any) {
	e.ev.Trace = append(e.ev.Trace, Step{Depth: depth, Domain: domain, Term: term, Note: fmt.Sprintf(format, args...)})
}

// validInitialDomain reports whether d is a well-formed multi-label domain
// (RFC 7208 section 4.3).
func validInitialDomain(d string) bool {
	return dnsresolver.ValidDomain(d) && strings.Contains(strings.TrimSuffix(d, "."), ".")
}

// FetchRecord retrieves the single SPF record of domain. It returns
// ResultNone when there is no record, and an *evalError-wrapped permerror or
// temperror for multiple records or lookup failures.
func fetchRecord(ctx context.Context, r dnsresolver.Resolver, domain string) (string, Result, error) {
	txts, err := r.LookupTXT(ctx, domain)
	switch {
	case dnsresolver.IsNXDomain(err):
		return "", ResultNone, nil
	case err != nil:
		return "", ResultTempError, tempErr("TXT lookup for %s failed: %v", domain, err)
	}
	var records []string
	for _, t := range txts {
		if IsSPF(t) {
			records = append(records, t)
		}
	}
	switch len(records) {
	case 0:
		return "", ResultNone, nil
	case 1:
		return records[0], "", nil
	default:
		return "", ResultPermError, permErr("%s publishes %d SPF records", domain, len(records))
	}
}

func (e *evaluator) checkHost(ctx context.Context, domain string, depth int) (Result, error) {
	if !validInitialDomain(domain) {
		e.trace(depth, domain, "", "domain is not a valid multi-label name: none")
		if depth == 0 {
			e.ev.Reason = "the domain is not a valid multi-label domain name"
		}
		return ResultNone, nil
	}
	for _, d := range e.stack {
		if strings.EqualFold(d, domain) {
			e.ev.LoopDetected = true
			chain := strings.Join(append(append([]string{}, e.stack...), domain), " -> ")
			e.trace(depth, domain, "", "loop detected: %s", chain)
			return ResultPermError, permErr("include/redirect loop: %s", chain)
		}
	}
	if depth > e.limits.MaxDepth {
		return ResultPermError, permErr("include/redirect nesting deeper than %d", e.limits.MaxDepth)
	}
	e.stack = append(e.stack, domain)
	defer func() { e.stack = e.stack[:len(e.stack)-1] }()

	txt, res, err := fetchRecord(ctx, e.resolver, domain)
	if err != nil {
		e.trace(depth, domain, "", "%v", err)
		return res, err
	}
	if res == ResultNone {
		e.trace(depth, domain, "", "no SPF record: none")
		if depth == 0 {
			e.ev.Reason = "no SPF record published for " + domain
		}
		return ResultNone, nil
	}
	rec, err := Parse(txt)
	if err != nil {
		e.trace(depth, domain, "", "syntax error: %v", err)
		return ResultPermError, permErr("syntax error in SPF record of %s: %v", domain, err)
	}
	e.trace(depth, domain, "", "record: %s", txt)

	mc := &macroContext{ip: e.req.IP, sender: e.req.Sender, domain: domain, helo: e.req.HELO, receiver: e.req.Receiver, now: e.req.Now}
	mc.ptr = func() string {
		// The "p" macro performs PTR and address lookups that do not count
		// towards the lookup limit; resolve it at most once per domain.
		if v, ok := e.pCache[domain]; ok {
			return v
		}
		v := e.pMacro(ctx, domain)
		e.pCache[domain] = v
		return v
	}

	for _, term := range rec.Terms {
		if term.Modifier {
			continue
		}
		if term.CountsLookup() {
			if err := e.countLookup(term); err != nil {
				e.trace(depth, domain, term.Raw, "%v", err)
				return ResultPermError, err
			}
		}
		matched, err := e.match(ctx, term, mc, depth)
		if err != nil {
			e.trace(depth, domain, term.Raw, "%v", err)
			return ResultPermError, err
		}
		if matched {
			result := term.Qualifier.Result()
			e.trace(depth, domain, term.Raw, "matched: %s", result)
			if depth == 0 {
				e.ev.MatchedTerm, e.ev.MatchedDomain = term.Raw, domain
				e.ev.Reason = fmt.Sprintf("%s matched %q in the SPF record of %s", e.req.IP, term.Raw, domain)
				if result == ResultFail && rec.Exp != nil {
					e.ev.Explanation = e.explanation(ctx, *rec.Exp, mc)
				}
			}
			return result, nil
		}
		e.trace(depth, domain, term.Raw, "no match")
	}

	if rec.Redirect != nil {
		if err := e.countLookup(*rec.Redirect); err != nil {
			return ResultPermError, err
		}
		target := rec.Redirect.expandDomain(mc)
		e.trace(depth, domain, rec.Redirect.Raw, "following redirect to %s", target)
		if !validInitialDomain(target) {
			return ResultPermError, permErr("redirect target %q is not a valid domain", target)
		}
		res, err := e.checkHost(ctx, target, depth+1)
		if err != nil {
			return res, err
		}
		if res == ResultNone {
			return ResultPermError, permErr("redirect target %s has no SPF record", target)
		}
		if depth == 0 && e.ev.Reason == "" {
			e.ev.Reason = fmt.Sprintf("result %s from redirect to %s", res, target)
		}
		return res, nil
	}
	e.trace(depth, domain, "", "no directive matched: neutral")
	if depth == 0 {
		e.ev.Reason = "no directive matched and there is no redirect; default result is neutral"
	}
	return ResultNeutral, nil
}

func (e *evaluator) countLookup(term Term) error {
	e.ev.Lookups++
	if e.ev.Lookups > e.limits.MaxLookups {
		e.ev.LookupLimitExceeded = true
		return permErr("more than %d DNS-querying terms (limit exceeded at %q)", e.limits.MaxLookups, term.Raw)
	}
	return nil
}

func (e *evaluator) countVoid(term Term, target string) error {
	e.ev.VoidLookups++
	if e.ev.VoidLookups > e.limits.MaxVoidLookups {
		e.ev.LookupLimitExceeded = true
		return permErr("more than %d void DNS lookups (at %q for %s)", e.limits.MaxVoidLookups, term.Raw, target)
	}
	return nil
}

// match evaluates a single mechanism. Temporary DNS failures are returned as
// temperror, which aborts evaluation.
func (e *evaluator) match(ctx context.Context, term Term, mc *macroContext, depth int) (bool, error) {
	ip := e.req.IP
	switch term.Name {
	case MechAll:
		return true, nil

	case MechIP4:
		return ip.Is4() && term.Network.Contains(ip), nil

	case MechIP6:
		return ip.Is6() && term.Network.Contains(ip), nil

	case MechInclude:
		target := term.expandDomain(mc)
		if !validInitialDomain(target) {
			return false, permErr("include target %q is not a valid domain", target)
		}
		res, err := e.checkHost(ctx, target, depth+1)
		if err != nil {
			return false, err
		}
		switch res {
		case ResultPass:
			return true, nil
		case ResultFail, ResultSoftFail, ResultNeutral:
			return false, nil
		case ResultNone:
			return false, permErr("include target %s has no SPF record", target)
		}
		return false, permErr("include of %s returned %s", target, res)

	case MechA:
		target := term.expandDomain(mc)
		addrs, err := e.lookupAddrs(ctx, target, ip)
		if err != nil {
			if dnsresolver.IsNXDomain(err) || dnsresolver.KindOf(err) == dnsresolver.KindInvalidName {
				return false, e.countVoid(term, target)
			}
			return false, tempErr("%s lookup for %s failed: %v", addrType(ip), target, err)
		}
		if len(addrs) == 0 {
			return false, e.countVoid(term, target)
		}
		return matchAddrs(addrs, ip, term), nil

	case MechMX:
		target := term.expandDomain(mc)
		mxs, err := e.resolver.LookupMX(ctx, target)
		if err != nil {
			if dnsresolver.IsNXDomain(err) || dnsresolver.KindOf(err) == dnsresolver.KindInvalidName {
				return false, e.countVoid(term, target)
			}
			return false, tempErr("MX lookup for %s failed: %v", target, err)
		}
		if len(mxs) == 0 {
			return false, e.countVoid(term, target)
		}
		if len(mxs) > e.limits.MaxMXNames {
			e.ev.LookupLimitExceeded = true
			return false, permErr("%s has %d MX records; the mx mechanism may consider at most %d", target, len(mxs), e.limits.MaxMXNames)
		}
		for _, mx := range mxs {
			if mx.Host == "." {
				continue
			}
			addrs, err := e.lookupAddrs(ctx, mx.Host, ip)
			if err != nil {
				if dnsresolver.IsTemporary(err) {
					return false, tempErr("%s lookup for MX host %s failed: %v", addrType(ip), mx.Host, err)
				}
				continue
			}
			if matchAddrs(addrs, ip, term) {
				return true, nil
			}
		}
		return false, nil

	case MechPTR:
		target := strings.ToLower(term.expandDomain(mc))
		names, err := ptrValidated(ctx, e, ip, e.limits.MaxPTRNames)
		if err != nil {
			if dnsresolver.IsTemporary(err) {
				// RFC 7208 section 5.5: a failing PTR lookup is "no match".
				e.trace(depth, mc.domain, term.Raw, "PTR lookup failed, treated as no match: %v", err)
			}
			return false, nil
		}
		for _, n := range names {
			if n == target || strings.HasSuffix(n, "."+target) {
				return true, nil
			}
		}
		return false, nil

	case MechExists:
		target := term.expandDomain(mc)
		addrs, err := e.resolver.LookupA(ctx, target)
		if err != nil {
			if dnsresolver.IsNXDomain(err) || dnsresolver.KindOf(err) == dnsresolver.KindInvalidName {
				return false, e.countVoid(term, target)
			}
			return false, tempErr("A lookup for %s failed: %v", target, err)
		}
		if len(addrs) == 0 {
			return false, e.countVoid(term, target)
		}
		return true, nil
	}
	return false, permErr("unsupported mechanism %q", term.Name)
}

func addrType(ip netip.Addr) string {
	if ip.Is4() {
		return "A"
	}
	return "AAAA"
}

// lookupAddrs resolves A records for IPv4 clients and AAAA for IPv6 clients.
func (e *evaluator) lookupAddrs(ctx context.Context, name string, ip netip.Addr) ([]netip.Addr, error) {
	if ip.Is4() {
		return e.resolver.LookupA(ctx, name)
	}
	return e.resolver.LookupAAAA(ctx, name)
}

func matchAddrs(addrs []netip.Addr, ip netip.Addr, term Term) bool {
	bits := term.CIDR4
	if ip.Is6() {
		bits = term.CIDR6
	}
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() != ip.Is4() {
			continue
		}
		if bits < 0 {
			if a == ip {
				return true
			}
			continue
		}
		if p, err := a.Prefix(bits); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

func (e *evaluator) pMacro(ctx context.Context, domain string) string {
	names, err := ptrValidated(ctx, e, e.req.IP, e.limits.MaxPTRNames)
	if err != nil || len(names) == 0 {
		return "unknown"
	}
	domain = strings.ToLower(domain)
	for _, n := range names {
		if n == domain {
			return n
		}
	}
	for _, n := range names {
		if strings.HasSuffix(n, "."+domain) {
			return n
		}
	}
	return names[0]
}

// explanation fetches and expands the exp= text. Failures yield "".
func (e *evaluator) explanation(ctx context.Context, exp Term, mc *macroContext) string {
	target := exp.expandDomain(mc)
	if !validInitialDomain(target) {
		return ""
	}
	txts, err := e.resolver.LookupTXT(ctx, target)
	if err != nil || len(txts) != 1 {
		return ""
	}
	m, err := parseMacroString(strings.ReplaceAll(txts[0], " ", "%_"), true)
	if err != nil {
		return ""
	}
	const maxExplanation = 512
	s := m.expand(mc)
	if len(s) > maxExplanation {
		s = s[:maxExplanation]
	}
	return s
}
