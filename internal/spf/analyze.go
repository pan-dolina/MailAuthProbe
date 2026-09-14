package spf

import (
	"context"
	"fmt"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

// Node is one record in the SPF dependency tree.
type Node struct {
	Domain string `json:"domain"`
	// Via is the term in the parent record that references this node
	// ("include:..." or "redirect=..."); empty for the root.
	Via    string `json:"via,omitempty"`
	Record string `json:"record,omitempty"`
	// Lookups is the number of DNS-querying terms in this record;
	// TotalLookups includes all descendants that would be evaluated.
	Lookups      int     `json:"lookups"`
	TotalLookups int     `json:"total_lookups"`
	VoidLookups  int     `json:"void_lookups"`
	Error        string  `json:"error,omitempty"`
	Loop         bool    `json:"loop,omitempty"`
	Dynamic      bool    `json:"dynamic,omitempty"`
	Children     []*Node `json:"children,omitempty"`
}

// Analysis is the static assessment of a domain's SPF policy.
type Analysis struct {
	Domain string `json:"domain"`
	// Record is the root SPF record, empty if none.
	Record       string             `json:"record,omitempty"`
	Tree         *Node              `json:"tree,omitempty"`
	TotalLookups int                `json:"total_lookups"`
	VoidLookups  int                `json:"void_lookups"`
	Findings     []findings.Finding `json:"-"`
}

// Analyzer performs static analysis of SPF policies for domain audits.
//
// Unlike check_host(), which stops at the first matching term for one client
// address, the analyzer walks every include and redirect to compute the
// worst-case number of DNS lookups a receiver may need, and reports problems
// anywhere in the dependency tree.
type Analyzer struct {
	Resolver dnsresolver.Resolver
	Limits   Limits
}

type analysisState struct {
	a        *Analyzer
	limits   Limits
	root     string
	findings []findings.Finding
	infraErr error
	perRule  map[string]int
	// nodes counts include/redirect targets fetched, bounding the work
	// done on hostile trees.
	nodes int
}

const maxAnalysisNodes = 64

// Analyze builds the dependency tree of domain's SPF policy. The returned
// error is non-nil for DNS infrastructure failures on the root record or on
// records referenced by include or redirect.
func (a *Analyzer) Analyze(ctx context.Context, domain string) (*Analysis, error) {
	limits := a.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits
	}
	domain = dnsresolver.Trim(domain)
	st := &analysisState{a: a, limits: limits, root: domain}
	res := &Analysis{Domain: domain}

	txts, err := a.Resolver.LookupTXT(ctx, domain)
	if err != nil && !dnsresolver.IsNXDomain(err) {
		st.add(findings.DNSLookupFailed.New(domain, "The TXT lookup for the SPF record failed.", err.Error()))
		res.Findings = st.findings
		return res, err
	}
	var records []string
	for _, t := range txts {
		if IsSPF(t) {
			records = append(records, t)
		}
	}
	switch len(records) {
	case 0:
		st.add(findings.SPFMissing.New(domain, fmt.Sprintf("%s does not publish an SPF record, so any host can claim to send its mail as far as SPF is concerned.", domain)))
		res.Findings = st.findings
		return res, nil
	case 1:
	default:
		st.add(findings.SPFMultiple.New(domain, fmt.Sprintf("%s publishes %d SPF records; receivers return permerror.", domain, len(records)), records...))
		res.Tree = &Node{Domain: domain, Error: fmt.Sprintf("%d SPF records", len(records))}
		res.Findings = st.findings
		return res, nil
	}

	res.Record = records[0]
	res.Tree = st.walk(ctx, domain, "", records[0], nil)
	res.TotalLookups = res.Tree.TotalLookups
	res.VoidLookups = sumVoids(res.Tree)

	switch {
	case res.TotalLookups > limits.MaxLookups:
		st.add(findings.SPFLookupLimit.New(domain,
			fmt.Sprintf("Evaluating the SPF policy of %s can require %d DNS lookups; the limit is %d.", domain, res.TotalLookups, limits.MaxLookups),
			lookupBreakdown(res.Tree)...))
	case res.TotalLookups >= limits.MaxLookups-2:
		st.add(findings.SPFLookupsNearLimit.New(domain,
			fmt.Sprintf("The SPF policy of %s needs up to %d of %d allowed DNS lookups.", domain, res.TotalLookups, limits.MaxLookups),
			lookupBreakdown(res.Tree)...))
	}
	if res.VoidLookups > limits.MaxVoidLookups {
		st.add(findings.SPFVoidLimit.New(domain, fmt.Sprintf("Evaluating the SPF policy of %s can hit %d void lookups; the recommended limit is %d.", domain, res.VoidLookups, limits.MaxVoidLookups)))
	}

	worst := findings.Max(st.findings)
	if worst < findings.SeverityMedium {
		st.add(findings.SPFValid.New(domain, fmt.Sprintf("The SPF record is valid and needs %d of %d DNS lookups.", res.TotalLookups, limits.MaxLookups), res.Record))
	}
	st.noteSuppressed()
	res.Findings = st.findings
	return res, st.infraErr
}

// maxFindingsPerRule caps repeated findings: a hostile tree can contain
// thousands of identical problems (for example 8000 "ptr" terms).
const maxFindingsPerRule = 20

func (st *analysisState) add(f findings.Finding) {
	if st.perRule == nil {
		st.perRule = map[string]int{}
	}
	st.perRule[f.ID]++
	if st.perRule[f.ID] > maxFindingsPerRule {
		return
	}
	st.findings = append(st.findings, f)
}

// noteSuppressed records how many findings of each rule were dropped.
func (st *analysisState) noteSuppressed() {
	for i := len(st.findings) - 1; i >= 0; i-- {
		f := st.findings[i]
		if n := st.perRule[f.ID]; n > maxFindingsPerRule {
			st.findings[i] = f.WithEvidence(fmt.Sprintf("%d further %s findings in this SPF tree are not listed", n-maxFindingsPerRule, f.ID))
			st.perRule[f.ID] = 0
		}
	}
}

func sumVoids(n *Node) int {
	total := n.VoidLookups
	for _, c := range n.Children {
		total += sumVoids(c)
	}
	return total
}

func lookupBreakdown(n *Node) []string {
	var out []string
	var walk func(n *Node, depth int)
	walk = func(n *Node, depth int) {
		label := n.Domain
		if n.Via != "" {
			label = n.Via
		}
		out = append(out, fmt.Sprintf("%s%s: %d lookup(s), %d in total", strings.Repeat("  ", depth), label, n.Lookups, n.TotalLookups))
		for _, c := range n.Children {
			walk(c, depth+1)
		}
	}
	walk(n, 0)
	return out
}

// walk analyses the record of domain. stack holds the domains being analysed
// on the current path, for loop detection.
func (st *analysisState) walk(ctx context.Context, domain, via, txt string, stack []string) *Node {
	node := &Node{Domain: domain, Via: via, Record: txt}
	stack = append(stack, strings.ToLower(domain))
	subject := domain

	if len(txt) > 450 {
		st.add(findings.SPFRecordTooLong.New(subject, fmt.Sprintf("The SPF record of %s is %d octets long.", domain, len(txt))))
	}

	rec, err := Parse(txt)
	if err != nil {
		node.Error = err.Error()
		f := findings.SPFSyntax.New(subject, fmt.Sprintf("The SPF record of %s contains syntax errors; it evaluates to permerror.", domain), txt)
		if se, ok := err.(*SyntaxError); ok {
			for i, te := range se.Errors {
				if i == 10 {
					f = f.WithEvidence(fmt.Sprintf("... and %d more syntax errors", len(se.Errors)-10))
					break
				}
				f = f.WithEvidence(te.Error())
			}
		}
		st.add(f)
		return node
	}

	mc := &macroContext{domain: domain}
	allSeen := false
	var afterAll []string
	for _, term := range rec.Terms {
		if !term.Modifier && allSeen {
			afterAll = append(afterAll, term.Raw)
			continue
		}
		if term.Modifier {
			st.checkModifier(term, domain)
			continue
		}
		st.checkDirective(term, domain)
		if term.macro.usesLetter('p') {
			st.add(findings.SPFPMacro.New(subject, fmt.Sprintf("%q in the SPF record of %s uses the p macro.", term.Raw, domain)))
		}
		if term.CountsLookup() {
			node.Lookups++
		}
		switch term.Name {
		case MechAll:
			allSeen = true
		case MechInclude:
			if child := st.follow(ctx, term, mc, domain, stack); child != nil {
				node.Children = append(node.Children, child)
			}
		case MechA, MechMX, MechExists:
			if st.isVoid(ctx, term, mc, domain) {
				node.VoidLookups++
			}
		}
	}
	if len(afterAll) > 0 {
		st.add(findings.SPFTermsAfterAll.New(subject, fmt.Sprintf("The SPF record of %s has mechanisms after \"all\" that can never match.", domain), afterAll...))
	}
	if rec.Redirect != nil {
		if allSeen {
			st.add(findings.SPFRedirectIgnored.New(subject, fmt.Sprintf("The SPF record of %s contains both \"all\" and %q; the redirect never takes effect.", domain, rec.Redirect.Raw)))
		} else {
			node.Lookups++
			if child := st.follow(ctx, *rec.Redirect, mc, domain, stack); child != nil {
				node.Children = append(node.Children, child)
			}
		}
	}
	if !allSeen && rec.Redirect == nil {
		f := findings.SPFNoAll.New(subject, fmt.Sprintf("The SPF record of %s ends without \"all\" or a redirect; hosts that match nothing get \"neutral\".", domain), txt)
		if len(stack) > 1 {
			// Inside an include, a missing "all" is harmless: non-matching
			// hosts make the include not match.
			f = f.WithSeverity(findings.SeverityInfo)
		}
		st.add(f)
	}

	node.TotalLookups = node.Lookups
	for _, c := range node.Children {
		node.TotalLookups += c.TotalLookups
	}
	return node
}

func (m macroString) usesLetter(letter byte) bool {
	for _, t := range m {
		if t.letter == letter {
			return true
		}
	}
	return false
}

// dynamicLetters are macros whose value depends on the message or client.
const dynamicLetters = "slopih"

func (m macroString) dynamic() bool {
	for _, t := range m {
		if t.letter != 0 && strings.IndexByte(dynamicLetters, t.letter) >= 0 {
			return true
		}
	}
	return false
}

func (st *analysisState) checkModifier(term Term, domain string) {
	switch term.Name {
	case ModRedirect:
	case ModExp:
		st.add(findings.SPFExp.New(domain, fmt.Sprintf("The SPF record of %s defines an explanation string (%s).", domain, term.Raw)))
	default:
		st.add(findings.SPFUnknownModifier.New(domain, fmt.Sprintf("The modifier %q is not defined by RFC 7208 and is ignored by receivers.", term.Raw)))
	}
}

func (st *analysisState) checkDirective(term Term, domain string) {
	root := strings.EqualFold(domain, st.root)
	switch term.Name {
	case MechAll:
		switch term.Qualifier {
		case QualifierPass:
			desc := fmt.Sprintf("The SPF record of %s ends with %q, which authorizes every IP address.", domain, term.Raw)
			if !root {
				desc = fmt.Sprintf("%s, included by %s, contains %q; the include matches every IP address, so %s authorizes the whole Internet.", domain, st.root, term.Raw, st.root)
			}
			st.add(findings.SPFPassAll.New(domain, desc))
		case QualifierNeutral:
			if root {
				st.add(findings.SPFNeutralAll.New(domain, fmt.Sprintf("The SPF record of %s ends with %q.", domain, term.Raw)))
			}
		case QualifierSoftFail:
			if root {
				st.add(findings.SPFSoftFailAll.New(domain, fmt.Sprintf("The SPF record of %s ends with %q.", domain, term.Raw)))
			}
		}
	case MechPTR:
		st.add(findings.SPFPTR.New(domain, fmt.Sprintf("The SPF record of %s uses %q.", domain, term.Raw)))
	case MechIP4, MechIP6, MechA, MechMX:
		if term.Qualifier == QualifierFail || term.Qualifier == QualifierSoftFail {
			return
		}
		type width struct{ bits, maxBits int }
		var widths []width
		switch term.Name {
		case MechIP4, MechIP6:
			widths = append(widths, width{term.Network.Bits(), term.Network.Addr().BitLen()})
		default:
			// a/0 or mx//0 turn a host lookup into "the whole Internet".
			if term.CIDR4 >= 0 {
				widths = append(widths, width{term.CIDR4, 32})
			}
			if term.CIDR6 >= 0 {
				widths = append(widths, width{term.CIDR6, 128})
			}
		}
		for _, w := range widths {
			if sev := broadRangeSeverity(w.bits, w.maxBits); sev != 0 {
				st.add(findings.SPFBroadRange.New(domain,
					fmt.Sprintf("%q in the SPF record of %s authorizes blocks of %s addresses.", term.Raw, domain, rangeSize(w.maxBits-w.bits)),
				).WithSeverity(sev))
			}
		}
	}
}

func broadRangeSeverity(bits, maxBits int) findings.Severity {
	if maxBits == 32 {
		switch {
		case bits == 0:
			return findings.SeverityCritical
		case bits <= 8:
			return findings.SeverityHigh
		case bits <= 16:
			return findings.SeverityMedium
		}
		return 0
	}
	switch {
	case bits == 0:
		return findings.SeverityCritical
	case bits <= 16:
		return findings.SeverityHigh
	case bits <= 32:
		return findings.SeverityMedium
	}
	return 0
}

func rangeSize(hostBits int) string {
	if hostBits < 63 {
		return fmt.Sprintf("%d", uint64(1)<<hostBits)
	}
	return fmt.Sprintf("2^%d", hostBits)
}

// follow analyses the target of an include or redirect.
func (st *analysisState) follow(ctx context.Context, term Term, mc *macroContext, parent string, stack []string) *Node {
	if term.macro.dynamic() {
		st.add(findings.SPFDynamic.New(parent, fmt.Sprintf("%q depends on the sender or client address and was counted but not followed.", term.Raw)))
		return &Node{Domain: term.Domain, Via: term.Raw, Dynamic: true}
	}
	target := strings.ToLower(term.expandDomain(mc))
	node := &Node{Domain: target, Via: term.Raw}
	for _, d := range stack {
		if d == target {
			node.Loop = true
			node.Error = "loop"
			chain := strings.Join(append(append([]string{}, stack...), target), " -> ")
			st.add(findings.SPFLoop.New(st.root, fmt.Sprintf("The SPF policy of %s contains a cycle: %s.", st.root, chain), chain))
			return node
		}
	}
	if len(stack) > st.limits.MaxDepth || st.nodes >= maxAnalysisNodes {
		node.Error = "not followed: analysis depth or size limit reached"
		return node
	}
	st.nodes++
	if !validInitialDomain(target) {
		node.Error = "invalid domain"
		st.add(findings.SPFSyntax.New(parent, fmt.Sprintf("%q expands to %q, which is not a valid domain.", term.Raw, target)))
		return node
	}

	txt, res, err := fetchRecord(ctx, st.a.Resolver, target)
	switch {
	case err != nil && res == ResultTempError:
		node.Error = err.Error()
		st.add(findings.SPFTempError.New(target, fmt.Sprintf("The SPF record of %s (referenced by %q in %s) could not be retrieved.", target, term.Raw, parent), err.Error()))
		if dnsresolver.IsInfrastructure(err) {
			st.infraErr = err
		}
		return node
	case err != nil:
		node.Error = err.Error()
		st.add(findings.SPFMultiple.New(target, fmt.Sprintf("%s, referenced by %q in %s, publishes multiple SPF records; the reference evaluates to permerror.", target, term.Raw, parent)))
		return node
	case res == ResultNone:
		node.Error = "no SPF record"
		st.add(findings.SPFIncludeNoRecord.New(target, fmt.Sprintf("%q in the SPF record of %s points at %s, which has no SPF record.", term.Raw, parent, target)))
		return node
	}
	child := st.walk(ctx, target, term.Raw, txt, stack)
	return child
}

// isVoid checks whether an a, mx or exists term targets a name without
// records. Dynamic targets are not resolved.
func (st *analysisState) isVoid(ctx context.Context, term Term, mc *macroContext, domain string) bool {
	if term.macro.dynamic() {
		st.add(findings.SPFDynamic.New(domain, fmt.Sprintf("%q depends on the sender or client address and was counted but not resolved.", term.Raw)))
		return false
	}
	target := term.expandDomain(mc)
	var empty bool
	var err error
	switch term.Name {
	case MechA:
		a, err4 := st.a.Resolver.LookupA(ctx, target)
		aaaa, err6 := st.a.Resolver.LookupAAAA(ctx, target)
		empty = len(a)+len(aaaa) == 0
		if dnsresolver.IsTemporary(err4) {
			err = err4
		} else if dnsresolver.IsTemporary(err6) {
			err = err6
		}
	case MechMX:
		var mxs []dnsresolver.MX
		mxs, err = st.a.Resolver.LookupMX(ctx, target)
		empty = len(mxs) == 0
		if len(mxs) > st.limits.MaxMXNames {
			st.add(findings.SPFMXLimit.New(domain, fmt.Sprintf("%q in the SPF record of %s resolves to %d MX records; receivers return permerror.", term.Raw, domain, len(mxs))))
		}
		if dnsresolver.IsNXDomain(err) {
			err = nil
		}
	case MechExists:
		a, e := st.a.Resolver.LookupA(ctx, target)
		empty, err = len(a) == 0, e
		if dnsresolver.IsNXDomain(err) {
			err = nil
		}
		// "exists" commonly targets names that intentionally do not exist.
		if empty {
			return true
		}
	}
	if err != nil && dnsresolver.IsTemporary(err) {
		st.add(findings.SPFTempError.New(target, fmt.Sprintf("Lookup for %q in the SPF record of %s failed.", term.Raw, domain), err.Error()))
		return false
	}
	if empty && term.Name != MechExists {
		st.add(findings.SPFVoidTarget.New(domain, fmt.Sprintf("%q in the SPF record of %s references %s, which has no matching records.", term.Raw, domain, target)))
	}
	return empty
}
