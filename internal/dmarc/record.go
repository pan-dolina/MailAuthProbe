// Package dmarc implements DMARC (RFC 7489): record parsing, policy
// discovery, identifier alignment, domain assessment and message evaluation.
package dmarc

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Policy is a requested handling policy.
type Policy string

// Policies.
const (
	PolicyNone       Policy = "none"
	PolicyQuarantine Policy = "quarantine"
	PolicyReject     Policy = "reject"
)

// Strength orders policies from weakest to strongest.
func (p Policy) Strength() int {
	switch p {
	case PolicyNone:
		return 1
	case PolicyQuarantine:
		return 2
	case PolicyReject:
		return 3
	}
	return 0
}

func parsePolicy(s string) (Policy, bool) {
	switch p := Policy(strings.ToLower(s)); p {
	case PolicyNone, PolicyQuarantine, PolicyReject:
		return p, true
	}
	return "", false
}

// Mode is an identifier alignment mode.
type Mode string

// Alignment modes.
const (
	ModeRelaxed Mode = "r"
	ModeStrict  Mode = "s"
)

// ReportURI is one destination from rua or ruf.
type ReportURI struct {
	URI     string `json:"uri"`
	Scheme  string `json:"scheme"`
	Address string `json:"address,omitempty"` // mailto: address
	Domain  string `json:"domain,omitempty"`  // domain of Address
	MaxSize string `json:"max_size,omitempty"`
}

// Tag is a raw tag=value pair in record order.
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// IssueKind classifies problems that do not invalidate a record.
type IssueKind int

// Issue kinds.
const (
	IssueInvalidValue IssueKind = iota + 1
	IssueDuplicateTag
	IssueUnknownTag
	IssueInvalidURI
)

// Issue is a non-fatal problem found while parsing.
type Issue struct {
	Kind IssueKind
	Tag  string
	Msg  string
}

// Record is a parsed DMARC record with defaults applied.
type Record struct {
	Raw  string `json:"raw"`
	Tags []Tag  `json:"tags"`

	Policy Policy `json:"p"`
	// SubdomainPolicy is the sp value, or empty when sp is absent.
	SubdomainPolicy Policy      `json:"sp,omitempty"`
	Percent         int         `json:"pct"`
	ADKIM           Mode        `json:"adkim"`
	ASPF            Mode        `json:"aspf"`
	RUA             []ReportURI `json:"rua,omitempty"`
	RUF             []ReportURI `json:"ruf,omitempty"`
	FO              []string    `json:"fo"`
	RF              string      `json:"rf"`
	RI              int         `json:"ri"`

	// PolicyImplied is set when p was missing or invalid but a valid rua
	// made the record usable as p=none (RFC 7489 section 6.6.3).
	PolicyImplied bool `json:"policy_implied,omitempty"`
	// Issues lists non-fatal problems.
	Issues []Issue `json:"-"`
}

// EffectiveSubdomainPolicy returns sp, defaulting to p.
func (r *Record) EffectiveSubdomainPolicy() Policy {
	if r.SubdomainPolicy != "" {
		return r.SubdomainPolicy
	}
	return r.Policy
}

// HasTag reports whether the record explicitly contains tag.
func (r *Record) HasTag(name string) bool {
	for _, t := range r.Tags {
		if t.Name == name {
			return true
		}
	}
	return false
}

// ParseError means the record is not a usable DMARC record.
type ParseError struct{ Msg string }

func (e *ParseError) Error() string { return "invalid DMARC record: " + e.Msg }

var versionRE = regexp.MustCompile(`^v[ \t]*=[ \t]*DMARC1[ \t]*(;|$)`)

// IsDMARC reports whether a TXT record claims to be a DMARC record, i.e.
// begins with the version tag "v=DMARC1".
func IsDMARC(txt string) bool { return versionRE.MatchString(txt) }

// Parse parses a DMARC record. It returns a *ParseError when the record
// cannot be used for policy decisions; other problems are recorded in
// Record.Issues.
func Parse(txt string) (*Record, error) {
	if !IsDMARC(txt) {
		return nil, &ParseError{Msg: `record must start with "v=DMARC1"`}
	}
	rec := &Record{
		Raw:     txt,
		Tags:    []Tag{},
		Percent: 100,
		ADKIM:   ModeRelaxed,
		ASPF:    ModeRelaxed,
		FO:      []string{"0"},
		RF:      "afrf",
		RI:      86400,
	}
	issue := func(kind IssueKind, tag, format string, args ...any) {
		rec.Issues = append(rec.Issues, Issue{Kind: kind, Tag: tag, Msg: fmt.Sprintf(format, args...)})
	}

	seen := map[string]bool{}
	pValid := false
	pPresent := false
	for i, part := range strings.Split(txt, ";") {
		part = strings.Trim(part, " \t\r\n")
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.ToLower(strings.Trim(name, " \t"))
		value = strings.Trim(value, " \t")
		if !ok || name == "" {
			return nil, &ParseError{Msg: fmt.Sprintf("malformed tag %q", part)}
		}
		if i == 0 {
			// Already validated by IsDMARC.
			rec.Tags = append(rec.Tags, Tag{Name: "v", Value: value})
			seen["v"] = true
			continue
		}
		rec.Tags = append(rec.Tags, Tag{Name: name, Value: value})
		if seen[name] {
			issue(IssueDuplicateTag, name, "tag %q appears more than once; only the first occurrence is used", name)
			continue
		}
		seen[name] = true

		switch name {
		case "v":
			// A second v tag is covered by the duplicate check above.
		case "p":
			pPresent = true
			if p, ok := parsePolicy(value); ok {
				rec.Policy = p
				pValid = true
			} else {
				issue(IssueInvalidValue, name, "invalid policy %q (want none, quarantine or reject)", value)
			}
		case "sp":
			if p, ok := parsePolicy(value); ok {
				rec.SubdomainPolicy = p
			} else {
				issue(IssueInvalidValue, name, "invalid subdomain policy %q; the p value applies instead", value)
			}
		case "np":
			if _, ok := parsePolicy(value); !ok {
				issue(IssueInvalidValue, name, "invalid non-existent subdomain policy %q", value)
			}
		case "pct":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 100 {
				issue(IssueInvalidValue, name, "pct must be an integer between 0 and 100, got %q; 100 applies", value)
			} else {
				rec.Percent = n
			}
		case "adkim", "aspf":
			m := Mode(strings.ToLower(value))
			if m != ModeRelaxed && m != ModeStrict {
				issue(IssueInvalidValue, name, "%s must be \"r\" or \"s\", got %q; relaxed applies", name, value)
				break
			}
			if name == "adkim" {
				rec.ADKIM = m
			} else {
				rec.ASPF = m
			}
		case "rua", "ruf":
			uris := parseURIs(value, func(msg string) { issue(IssueInvalidURI, name, "%s", msg) })
			if name == "rua" {
				rec.RUA = uris
			} else {
				rec.RUF = uris
			}
		case "fo":
			var opts []string
			valid := value != ""
			for o := range strings.SplitSeq(value, ":") {
				o = strings.Trim(o, " \t")
				switch o {
				case "0", "1", "d", "s":
					opts = append(opts, o)
				default:
					valid = false
				}
			}
			if !valid {
				issue(IssueInvalidValue, name, "fo must be a colon-separated list of 0, 1, d and s, got %q", value)
			}
			if len(opts) > 0 {
				rec.FO = opts
			}
		case "rf":
			for f := range strings.SplitSeq(value, ":") {
				if strings.ToLower(strings.Trim(f, " \t")) != "afrf" {
					issue(IssueInvalidValue, name, "unsupported report format %q (only afrf is defined)", value)
					break
				}
			}
			rec.RF = value
		case "ri":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				issue(IssueInvalidValue, name, "ri must be a non-negative integer, got %q", value)
			} else {
				rec.RI = int(n)
			}
		case "psd":
			if v := strings.ToLower(value); v != "y" && v != "n" && v != "u" {
				issue(IssueInvalidValue, name, "psd must be y, n or u, got %q", value)
			}
		case "t":
			if v := strings.ToLower(value); v != "y" && v != "n" {
				issue(IssueInvalidValue, name, "t must be y or n, got %q", value)
			}
		default:
			// np, psd and t (DMARCbis) are handled above; everything else
			// is unknown.
			issue(IssueUnknownTag, name, "unknown tag %q is ignored", name)
		}
	}

	if !pValid {
		hasValidRUA := len(rec.RUA) > 0
		if !hasValidRUA {
			if pPresent {
				return nil, &ParseError{Msg: "invalid p tag and no valid rua"}
			}
			return nil, &ParseError{Msg: "required tag p is missing"}
		}
		rec.Policy = PolicyNone
		rec.PolicyImplied = true
	}
	return rec, nil
}

var sizeRE = regexp.MustCompile(`^[0-9]+[kKmMgGtT]?$`)

func parseURIs(value string, issue func(string)) []ReportURI {
	var out []ReportURI
	for raw := range strings.SplitSeq(value, ",") {
		raw = strings.Trim(raw, " \t")
		if raw == "" {
			issue("empty report URI")
			continue
		}
		u := ReportURI{URI: raw}
		if i := strings.LastIndexByte(raw, '!'); i >= 0 {
			if !sizeRE.MatchString(raw[i+1:]) {
				issue(fmt.Sprintf("invalid size limit in %q", raw))
				continue
			}
			u.MaxSize = raw[i+1:]
			raw = raw[:i]
		}
		scheme, rest, ok := strings.Cut(raw, ":")
		if !ok || scheme == "" || rest == "" {
			issue(fmt.Sprintf("%q is not a URI", u.URI))
			continue
		}
		u.Scheme = strings.ToLower(scheme)
		switch u.Scheme {
		case "mailto":
			addr, _, _ := strings.Cut(rest, "?")
			addr = strings.ReplaceAll(addr, "%40", "@")
			local, domain, ok := strings.Cut(addr, "@")
			if !ok || local == "" || !validDomain(domain) {
				issue(fmt.Sprintf("%q is not a valid mailto URI", u.URI))
				continue
			}
			u.Address = addr
			u.Domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		case "https", "http":
			if !strings.HasPrefix(rest, "//") || len(rest) < 3 {
				issue(fmt.Sprintf("%q is not a valid %s URI", u.URI, u.Scheme))
				continue
			}
		default:
			issue(fmt.Sprintf("unsupported report URI scheme %q in %q", u.Scheme, u.URI))
			continue
		}
		out = append(out, u)
	}
	return out
}

func validDomain(d string) bool {
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
