// Package spf implements the Sender Policy Framework (RFC 7208): record
// parsing, macro expansion, check_host() evaluation and static analysis of a
// domain's SPF dependency tree.
package spf

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Qualifier is the result a matching mechanism produces.
type Qualifier byte

// Qualifiers.
const (
	QualifierPass     Qualifier = '+'
	QualifierFail     Qualifier = '-'
	QualifierSoftFail Qualifier = '~'
	QualifierNeutral  Qualifier = '?'
)

// Result returns the check_host() result for a match with this qualifier.
func (q Qualifier) Result() Result {
	switch q {
	case QualifierFail:
		return ResultFail
	case QualifierSoftFail:
		return ResultSoftFail
	case QualifierNeutral:
		return ResultNeutral
	default:
		return ResultPass
	}
}

// Result is a check_host() result (RFC 7208 section 2.6).
type Result string

// Results.
const (
	ResultNone      Result = "none"
	ResultNeutral   Result = "neutral"
	ResultPass      Result = "pass"
	ResultFail      Result = "fail"
	ResultSoftFail  Result = "softfail"
	ResultTempError Result = "temperror"
	ResultPermError Result = "permerror"
)

// Mechanism names.
const (
	MechAll     = "all"
	MechInclude = "include"
	MechA       = "a"
	MechMX      = "mx"
	MechPTR     = "ptr"
	MechIP4     = "ip4"
	MechIP6     = "ip6"
	MechExists  = "exists"
)

// Modifier names defined by RFC 7208.
const (
	ModRedirect = "redirect"
	ModExp      = "exp"
)

// Term is a directive (qualifier + mechanism) or a modifier.
type Term struct {
	// Raw is the term as it appears in the record.
	Raw string `json:"raw"`

	// Modifier is true for name=value terms.
	Modifier bool `json:"modifier,omitempty"`
	// Name is the lower-case mechanism or modifier name.
	Name string `json:"name"`

	// Qualifier of a directive. Zero for modifiers.
	Qualifier Qualifier `json:"-"`
	// Domain is the unexpanded domain-spec (include, exists, a, mx, ptr,
	// redirect, exp). Empty when the mechanism defaults to the current domain.
	Domain string `json:"domain,omitempty"`
	// Network is the address and prefix of an ip4 or ip6 mechanism.
	Network netip.Prefix `json:"-"`
	// CIDR4 and CIDR6 are the dual-cidr-length of a and mx mechanisms, or -1
	// when not given.
	CIDR4 int `json:"-"`
	CIDR6 int `json:"-"`
	// Value is the raw value of an unknown modifier.
	Value string `json:"-"`

	macro macroString
}

// String returns the raw term.
func (t Term) String() string { return t.Raw }

// HasMacros reports whether the term's domain-spec contains macros.
func (t Term) HasMacros() bool { return t.macro.hasMacros() }

// CountsLookup reports whether evaluating the term counts towards the limit
// of 10 DNS-querying terms (RFC 7208 section 4.6.4).
func (t Term) CountsLookup() bool {
	if t.Modifier {
		return t.Name == ModRedirect
	}
	switch t.Name {
	case MechInclude, MechA, MechMX, MechPTR, MechExists:
		return true
	}
	return false
}

// Record is a parsed SPF record.
type Record struct {
	Raw   string `json:"raw"`
	Terms []Term `json:"terms"`
	// Redirect and Exp point into Terms when the modifiers are present.
	Redirect *Term `json:"-"`
	Exp      *Term `json:"-"`
}

// Directives returns the mechanism terms in order.
func (r *Record) Directives() []Term {
	var out []Term
	for _, t := range r.Terms {
		if !t.Modifier {
			out = append(out, t)
		}
	}
	return out
}

// All returns the first "all" directive, if any.
func (r *Record) All() (Term, bool) {
	for _, t := range r.Terms {
		if !t.Modifier && t.Name == MechAll {
			return t, true
		}
	}
	return Term{}, false
}

// TermError describes a syntax error in one term.
type TermError struct {
	Term string
	Msg  string
}

func (e TermError) Error() string {
	if e.Term == "" {
		return e.Msg
	}
	return fmt.Sprintf("%q: %s", e.Term, e.Msg)
}

// SyntaxError lists every syntax problem found in a record. Per RFC 7208
// section 4.6 a record with any syntax error yields "permerror".
type SyntaxError struct {
	Errors []TermError
}

func (e *SyntaxError) Error() string {
	msgs := make([]string, len(e.Errors))
	for i, te := range e.Errors {
		msgs[i] = te.Error()
	}
	return "spf syntax error: " + strings.Join(msgs, "; ")
}

const versionTag = "v=spf1"

// IsSPF reports whether a TXT record is an SPF version 1 record, i.e. starts
// with "v=spf1" (case-insensitively) followed by a space or the end of the
// record (RFC 7208 section 4.5).
func IsSPF(txt string) bool {
	if len(txt) < len(versionTag) || !strings.EqualFold(txt[:len(versionTag)], versionTag) {
		return false
	}
	return len(txt) == len(versionTag) || txt[len(versionTag)] == ' '
}

// Parse parses an SPF record. When the record contains syntax errors, Parse
// returns the terms that could be parsed together with a *SyntaxError.
func Parse(txt string) (*Record, error) {
	if !IsSPF(txt) {
		return nil, &SyntaxError{Errors: []TermError{{Msg: `record does not start with "v=spf1"`}}}
	}
	rec := &Record{Raw: txt}
	var errs []TermError
	fail := func(term, format string, args ...any) {
		errs = append(errs, TermError{Term: term, Msg: fmt.Sprintf(format, args...)})
	}

	for _, raw := range strings.Split(txt[len(versionTag):], " ") {
		if raw == "" {
			continue
		}
		term, err := parseTerm(raw)
		if err != nil {
			fail(raw, "%s", err)
			continue
		}
		if term.Modifier && (term.Name == ModRedirect || term.Name == ModExp) {
			dup := (term.Name == ModRedirect && rec.Redirect != nil) || (term.Name == ModExp && rec.Exp != nil)
			if dup {
				fail(raw, "%s modifier appears more than once", term.Name)
				continue
			}
		}
		rec.Terms = append(rec.Terms, term)
		if term.Modifier && term.Name == ModRedirect {
			rec.Redirect = &term
		}
		if term.Modifier && term.Name == ModExp {
			rec.Exp = &term
		}
	}
	// Point the modifiers into the final Terms slice.
	for i := range rec.Terms {
		t := &rec.Terms[i]
		if t.Modifier && t.Name == ModRedirect {
			rec.Redirect = t
		}
		if t.Modifier && t.Name == ModExp {
			rec.Exp = t
		}
	}
	if len(errs) > 0 {
		return rec, &SyntaxError{Errors: errs}
	}
	return rec, nil
}

func parseTerm(raw string) (Term, error) {
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c < 0x21 || c > 0x7e {
			return Term{}, fmt.Errorf("invalid character 0x%02x", c)
		}
	}
	t := Term{Raw: raw, CIDR4: -1, CIDR6: -1}

	// A modifier's name is followed by '='; a mechanism's name by ':' or '/'
	// or the end of the term.
	nameEnd := strings.IndexAny(raw, ":/=")
	if nameEnd >= 0 && raw[nameEnd] == '=' {
		return parseModifier(t, raw[:nameEnd], raw[nameEnd+1:])
	}

	body := raw
	switch raw[0] {
	case '+', '-', '~', '?':
		t.Qualifier = Qualifier(raw[0])
		body = raw[1:]
	default:
		t.Qualifier = QualifierPass
	}
	name, arg := body, ""
	hasArg := false
	if i := strings.IndexAny(body, ":/"); i >= 0 {
		name, arg = body[:i], body[i:]
		hasArg = true
	}
	t.Name = strings.ToLower(name)

	switch t.Name {
	case MechAll:
		if hasArg {
			return t, errors.New(`"all" takes no arguments`)
		}
	case MechInclude, MechExists:
		if !strings.HasPrefix(arg, ":") || len(arg) < 2 {
			return t, fmt.Errorf("%q requires a domain-spec", t.Name)
		}
		if err := t.setDomain(arg[1:]); err != nil {
			return t, err
		}
	case MechA, MechMX:
		if err := t.parseDomainAndCIDR(arg); err != nil {
			return t, err
		}
	case MechPTR:
		if hasArg {
			if !strings.HasPrefix(arg, ":") || len(arg) < 2 {
				return t, errors.New(`"ptr" accepts only an optional domain-spec`)
			}
			if err := t.setDomain(arg[1:]); err != nil {
				return t, err
			}
		}
	case MechIP4, MechIP6:
		if !strings.HasPrefix(arg, ":") || len(arg) < 2 {
			return t, fmt.Errorf("%q requires a network", t.Name)
		}
		if err := t.parseNetwork(arg[1:]); err != nil {
			return t, err
		}
	case "":
		return t, errors.New("missing mechanism name")
	default:
		return t, fmt.Errorf("unknown mechanism %q", name)
	}
	return t, nil
}

func parseModifier(t Term, name, value string) (Term, error) {
	t.Modifier = true
	t.Name = strings.ToLower(name)
	if !validModifierName(name) {
		return t, fmt.Errorf("invalid modifier name %q", name)
	}
	switch t.Name {
	case ModRedirect, ModExp:
		if value == "" {
			return t, fmt.Errorf("%q requires a domain-spec", t.Name)
		}
		if err := t.setDomain(value); err != nil {
			return t, err
		}
	default:
		// Unknown modifiers are ignored, but their value must still be a
		// valid macro-string (RFC 7208 section 6).
		m, err := parseMacroString(value, true)
		if err != nil {
			return t, err
		}
		t.Value = value
		t.macro = m
	}
	return t, nil
}

// validModifierName: ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ).
func validModifierName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func (t *Term) setDomain(spec string) error {
	// The c, r and t macro letters are only allowed in the explanation
	// text fetched through exp=, not in any domain-spec, including exp's own
	// (RFC 7208 section 7.1).
	m, err := parseMacroString(spec, false)
	if err != nil {
		return err
	}
	if !m.validDomainEnd() {
		return fmt.Errorf("invalid domain-spec %q", spec)
	}
	t.Domain = spec
	t.macro = m
	return nil
}

// parseDomainAndCIDR parses [ ":" domain-spec ] [ dual-cidr-length ].
func (t *Term) parseDomainAndCIDR(arg string) error {
	if arg == "" {
		return nil
	}
	spec := arg
	if spec[0] == ':' {
		spec = spec[1:]
	} else if spec[0] != '/' {
		return fmt.Errorf("unexpected %q after %q", arg, t.Name)
	}

	// dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ], i.e.
	// "/n", "//m" or "/n//m" at the end of the term. '/' is also a valid
	// macro delimiter ("%{l/}"), so only text after the last macro is
	// searched.
	base := strings.LastIndexByte(spec, '}') + 1
	if i := strings.Index(spec[base:], "//"); i >= 0 {
		i += base
		v6, err := parseCIDR(spec[i+2:], 128)
		if err != nil {
			return fmt.Errorf("invalid ip6-cidr-length: %w", err)
		}
		t.CIDR6 = v6
		spec = spec[:i]
	}
	if i := strings.LastIndexByte(spec, '/'); i >= base {
		v4, err := parseCIDR(spec[i+1:], 32)
		if err != nil {
			return fmt.Errorf("invalid ip4-cidr-length: %w", err)
		}
		t.CIDR4 = v4
		spec = spec[:i]
	}
	if arg[0] == ':' {
		if spec == "" {
			return fmt.Errorf("%q has an empty domain-spec", t.Name)
		}
		return t.setDomain(spec)
	}
	if spec != "" {
		return fmt.Errorf("unexpected %q", spec)
	}
	return nil
}

func parseCIDR(s string, maxBits int) (int, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("%q", s)
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, fmt.Errorf("%q", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > maxBits {
		return 0, fmt.Errorf("%q out of range 0-%d", s, maxBits)
	}
	return n, nil
}

func (t *Term) parseNetwork(s string) error {
	addrPart, bitsPart, hasBits := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrPart)
	if err != nil || addr.Zone() != "" {
		return fmt.Errorf("invalid %s address %q", t.Name, addrPart)
	}
	maxBits := 32
	if t.Name == MechIP4 {
		if !addr.Is4() {
			return fmt.Errorf("ip4 requires an IPv4 address, got %q", addrPart)
		}
	} else {
		if !addr.Is6() {
			return fmt.Errorf("ip6 requires an IPv6 address, got %q", addrPart)
		}
		maxBits = 128
	}
	bits := maxBits
	if hasBits {
		if bits, err = parseCIDR(bitsPart, maxBits); err != nil {
			return fmt.Errorf("invalid prefix length: %w", err)
		}
	}
	t.Network = netip.PrefixFrom(addr, bits).Masked()
	return nil
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
