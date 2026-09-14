package authres

import (
	"fmt"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

// ComputedDKIM is an independently verified signature.
type ComputedDKIM struct {
	Domain   string
	Selector string
	HeaderB  string
	Result   string
}

// Computed holds MailAuthProbe's own verdicts.
type Computed struct {
	// SPF is empty when SPF was not evaluated.
	SPF         string
	SPFInferred bool
	DKIM        []ComputedDKIM
	// DMARC is empty when DMARC was not evaluated.
	DMARC string
}

// Parsed is an Authentication-Results header with its position.
type Parsed struct {
	// Index is the position among Authentication-Results headers, 1 being
	// the topmost (most recently added).
	Index  int     `json:"index"`
	Header *Header `json:"header,omitempty"`
	Error  string  `json:"error,omitempty"`
	Raw    string  `json:"raw"`
}

// ParseAll parses header values in message order.
func ParseAll(values []string) []Parsed {
	out := make([]Parsed, 0, len(values))
	for i, v := range values {
		p := Parsed{Index: i + 1, Raw: v}
		if h, err := Parse(v); err != nil {
			p.Error = err.Error()
		} else {
			p.Header = h
		}
		out = append(out, p)
	}
	return out
}

// Compare checks Authentication-Results headers for internal conflicts and
// for disagreement with the computed results.
func Compare(parsed []Parsed, c Computed) []findings.Finding {
	var fs []findings.Finding
	add := func(f findings.Finding) { fs = append(fs, f) }
	if len(parsed) == 0 {
		add(findings.ARNone.New("", "The message carries no Authentication-Results headers to compare with."))
		return fs
	}

	// Conflicts between headers claiming the same authserv-id.
	type claim struct {
		result string
		index  int
	}
	claims := map[string]map[string][]claim{} // authserv-id -> method key -> claims
	for _, p := range parsed {
		if p.Header == nil {
			add(findings.ARUnparseable.New("", fmt.Sprintf("Authentication-Results header #%d: %s.", p.Index, p.Error), p.Raw))
			continue
		}
		id := p.Header.AuthServID
		if claims[id] == nil {
			claims[id] = map[string][]claim{}
		}
		for _, r := range p.Header.Results {
			key := r.Method
			if r.Method == "dkim" {
				key += " " + firstNonEmpty(r.Prop("header.b"), r.Prop("header.d"), r.Prop("header.i"))
			}
			claims[id][key] = append(claims[id][key], claim{r.Result, p.Index})
		}
	}
	for _, p := range parsed {
		if p.Header == nil {
			continue
		}
		id := p.Header.AuthServID
		for key, cs := range claims[id] {
			if len(cs) < 2 || cs[0].index != p.Index {
				continue
			}
			for _, other := range cs[1:] {
				if other.result != cs[0].result {
					add(findings.ARConflict.New(displayID(id),
						fmt.Sprintf("Authentication-Results headers #%d and #%d from %s report %s=%s and %s=%s.", cs[0].index, other.index, displayID(id), strings.TrimSpace(key), cs[0].result, strings.TrimSpace(key), other.result)))
					break
				}
			}
		}
	}

	// Compare the topmost parsable header (added last, normally by the
	// receiving MTA) with the computed results.
	var top *Parsed
	for i := range parsed {
		if parsed[i].Header != nil && !parsed[i].Header.None {
			top = &parsed[i]
			break
		}
	}
	if top == nil {
		return fs
	}
	h := top.Header
	var diffs, agree []string
	check := func(method, claimed, computed, note string) {
		if claimed == "" || computed == "" {
			return
		}
		if normalizeResult(claimed) == normalizeResult(computed) {
			agree = append(agree, fmt.Sprintf("%s=%s", method, computed))
			return
		}
		diffs = append(diffs, fmt.Sprintf("%s: header says %s, MailAuthProbe computed %s%s", method, claimed, computed, note))
	}
	if rs := h.ByMethod("spf"); len(rs) > 0 {
		note := ""
		if c.SPFInferred {
			note = " (SPF inputs inferred from headers)"
		}
		check("spf", rs[0].Result, c.SPF, note)
	}
	if rs := h.ByMethod("dmarc"); len(rs) > 0 {
		check("dmarc", rs[0].Result, c.DMARC, "")
	}
	for _, r := range h.ByMethod("dkim") {
		if d, ok := matchDKIM(r, c.DKIM); ok {
			check("dkim d="+d.Domain, r.Result, d.Result, "")
		} else if r.Result == "pass" {
			diffs = append(diffs, fmt.Sprintf("dkim: header reports a passing signature for %s that is not present in the message", firstNonEmpty(r.Prop("header.d"), r.Prop("header.i"), "an unknown domain")))
		}
	}

	subject := displayID(h.AuthServID)
	switch {
	case len(diffs) > 0:
		add(findings.ARMismatch.New(subject, fmt.Sprintf("Authentication-Results header #%d (%s) disagrees with independent verification.", top.Index, subject), diffs...))
	case len(agree) > 0:
		add(findings.ARConsistent.New(subject, fmt.Sprintf("Authentication-Results header #%d (%s) matches independent verification.", top.Index, subject), agree...))
	}
	return fs
}

func matchDKIM(r Result, computed []ComputedDKIM) (ComputedDKIM, bool) {
	if b := r.Prop("header.b"); b != "" {
		for _, c := range computed {
			if c.HeaderB != "" && (strings.HasPrefix(c.HeaderB, b) || strings.HasPrefix(b, c.HeaderB)) {
				return c, true
			}
		}
	}
	d := strings.ToLower(r.Prop("header.d"))
	if d == "" {
		if i := r.Prop("header.i"); i != "" {
			d = strings.ToLower(i[strings.LastIndexByte(i, '@')+1:])
		}
	}
	s := strings.ToLower(r.Prop("header.s"))
	for _, c := range computed {
		if d != "" && strings.EqualFold(c.Domain, d) && (s == "" || strings.EqualFold(c.Selector, s)) {
			return c, true
		}
	}
	return ComputedDKIM{}, false
}

// normalizeResult maps equivalent result spellings.
func normalizeResult(r string) string {
	switch r = strings.ToLower(r); r {
	case "hardfail":
		return "fail"
	case "bestguesspass":
		return "pass"
	}
	return r
}

func displayID(id string) string {
	if id == "" {
		return "(no authserv-id)"
	}
	return id
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
