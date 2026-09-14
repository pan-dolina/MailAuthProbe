// Package authres parses Authentication-Results (RFC 8601) and Received-SPF
// (RFC 7208 section 9.1) header fields.
//
// These headers are untrusted: anyone can add them before a message reaches
// the receiving organization. MailAuthProbe parses them only to compare the
// claims with its own independent evaluation.
package authres

import (
	"errors"
	"fmt"
	"strings"
)

// Result is one method result inside an Authentication-Results header.
type Result struct {
	Method  string `json:"method"`
	Version string `json:"version,omitempty"`
	Result  string `json:"result"`
	Reason  string `json:"reason,omitempty"`
	// Props maps "ptype.property" (lower case) to the value, e.g.
	// "header.d" -> "example.com".
	Props map[string]string `json:"properties,omitempty"`
}

// Prop returns a property value.
func (r Result) Prop(name string) string { return r.Props[strings.ToLower(name)] }

// Header is a parsed Authentication-Results header field.
type Header struct {
	AuthServID string   `json:"authserv_id"`
	Version    string   `json:"version,omitempty"`
	Results    []Result `json:"results"`
	// None is set for "authserv-id; none".
	None bool `json:"none,omitempty"`
}

// ByMethod returns the results for a method, in order.
func (h *Header) ByMethod(method string) []Result {
	var out []Result
	for _, r := range h.Results {
		if strings.EqualFold(r.Method, method) {
			out = append(out, r)
		}
	}
	return out
}

// Parse parses an Authentication-Results header value.
func Parse(value string) (*Header, error) {
	clean, err := stripComments(value)
	if err != nil {
		return nil, err
	}
	parts := splitUnquoted(clean, ';')
	head := strings.Fields(parts[0])
	if len(head) == 0 {
		return nil, errors.New("missing authserv-id")
	}
	h := &Header{Results: []Result{}}
	rest := parts[1:]
	if strings.Contains(head[0], "=") {
		// No authserv-id, as written by Exchange Online. Not valid RFC 8601,
		// but common enough to accept.
		rest = parts
	} else {
		h.AuthServID = strings.ToLower(unquote(head[0]))
	}
	if h.AuthServID != "" && len(head) > 1 {
		h.Version = head[1]
		if len(head) > 2 {
			return nil, fmt.Errorf("unexpected text after authserv-id: %q", strings.Join(head[2:], " "))
		}
	}
	if len(rest) == 1 && strings.EqualFold(strings.TrimSpace(rest[0]), "none") {
		h.None = true
		return h, nil
	}
	for _, part := range rest {
		if strings.TrimSpace(part) == "" {
			continue
		}
		r, err := parseResInfo(part)
		if err != nil {
			return nil, err
		}
		h.Results = append(h.Results, r)
	}
	return h, nil
}

func parseResInfo(s string) (Result, error) {
	tokens := tokenizeAssignments(s)
	if len(tokens) == 0 {
		return Result{}, fmt.Errorf("empty result in %q", strings.TrimSpace(s))
	}
	method, result, ok := strings.Cut(tokens[0], "=")
	if !ok || method == "" || result == "" {
		return Result{}, fmt.Errorf("invalid method result %q", tokens[0])
	}
	r := Result{Result: strings.ToLower(unquote(result)), Props: map[string]string{}}
	r.Method, r.Version, _ = strings.Cut(strings.ToLower(method), "/")
	// Validate after unquoting: `spf=""` must not yield an empty result.
	if !isKeyword(r.Method) || !isKeyword(r.Result) {
		return Result{}, fmt.Errorf("invalid method result %q", tokens[0])
	}
	for _, tok := range tokens[1:] {
		name, val, ok := strings.Cut(tok, "=")
		if !ok {
			return Result{}, fmt.Errorf("invalid property %q", tok)
		}
		name = strings.ToLower(name)
		val = unquote(val)
		if name == "reason" {
			r.Reason = val
			continue
		}
		// RFC 8601 properties are "ptype.property"; bare names such as
		// Microsoft's "action=none" are kept as they are.
		if _, dup := r.Props[name]; !dup {
			r.Props[name] = val
		}
	}
	return r, nil
}

// isKeyword reports whether s is a method or result keyword: letters,
// digits, '-' and '_' (RFC 8601 section 2.2).
func isKeyword(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// tokenizeAssignments splits "a = b c.d= e" into ["a=b", "c.d=e"], keeping
// quoted strings intact.
func tokenizeAssignments(s string) []string {
	var words []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(s):
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case !inQuote && (c == ' ' || c == '\t' || c == '\r' || c == '\n'):
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		case !inQuote && c == '=':
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
			words = append(words, "=")
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	// Join name "=" value triples.
	var out []string
	for i := 0; i < len(words); i++ {
		if i+2 < len(words) && words[i+1] == "=" && words[i] != "=" && words[i+2] != "=" {
			out = append(out, words[i]+"="+words[i+2])
			i += 2
			continue
		}
		out = append(out, words[i])
	}
	return out
}

// stripComments removes RFC 5322 comments outside quoted strings.
func stripComments(s string) (string, error) {
	var b strings.Builder
	depth := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			if depth == 0 {
				b.WriteByte(c)
				b.WriteByte(s[i+1])
			}
			i++
		case c == '"' && depth == 0:
			inQuote = !inQuote
			b.WriteByte(c)
		case c == '(' && !inQuote:
			depth++
			if depth > 32 {
				return "", errors.New("comments nested too deeply")
			}
		case c == ')' && !inQuote && depth > 0:
			depth--
			b.WriteByte(' ')
		default:
			if depth == 0 {
				b.WriteByte(c)
			}
		}
	}
	if inQuote {
		return "", errors.New("unterminated quoted string")
	}
	if depth > 0 {
		return "", errors.New("unterminated comment")
	}
	return b.String(), nil
}

func splitUnquoted(s string, sep byte) []string {
	var parts []string
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && inQuote:
			i++
		case s[i] == '"':
			inQuote = !inQuote
		case s[i] == sep && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	return s
}

// ReceivedSPF is a parsed Received-SPF header field.
type ReceivedSPF struct {
	Result  string            `json:"result"`
	Comment string            `json:"comment,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
}

// ParseReceivedSPF parses a Received-SPF header value.
func ParseReceivedSPF(value string) (*ReceivedSPF, error) {
	value = strings.TrimSpace(value)
	resultWord, rest, _ := strings.Cut(value, " ")
	result := strings.ToLower(strings.TrimRight(resultWord, ";"))
	switch result {
	case "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror":
	default:
		return nil, fmt.Errorf("unknown Received-SPF result %q", resultWord)
	}
	r := &ReceivedSPF{Result: result, Params: map[string]string{}}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") {
		depth := 0
		for i := 0; i < len(rest); i++ {
			if rest[i] == '(' {
				depth++
			} else if rest[i] == ')' {
				depth--
				if depth == 0 {
					r.Comment = rest[1:i]
					rest = rest[i+1:]
					break
				}
			}
		}
		if depth != 0 {
			return nil, errors.New("unterminated comment in Received-SPF")
		}
	}
	clean, err := stripComments(rest)
	if err != nil {
		return nil, err
	}
	for _, part := range splitUnquoted(clean, ';') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		r.Params[strings.ToLower(strings.TrimSpace(name))] = unquote(strings.TrimSpace(val))
	}
	return r, nil
}
