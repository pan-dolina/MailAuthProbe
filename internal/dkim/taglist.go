// Package dkim implements DomainKeys Identified Mail (RFC 6376): key record
// parsing, DKIM-Signature parsing, canonicalization and cryptographic
// verification, including Ed25519 (RFC 8463) and the algorithm requirements
// of RFC 8301.
package dkim

import (
	"fmt"
	"strings"
)

// tag is one tag=value pair.
type tag struct {
	name  string
	value string
}

// parseTagList parses a DKIM tag-list (RFC 6376 section 3.2). Whitespace
// around names and values is removed; duplicate tag names make the whole
// list invalid.
func parseTagList(s string) ([]tag, error) {
	var tags []tag
	seen := map[string]bool{}
	for part := range strings.SplitSeq(s, ";") {
		if strings.Trim(part, " \t\r\n") == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed tag %q", strings.TrimSpace(part))
		}
		name = strings.Trim(name, " \t\r\n")
		if !validTagName(name) {
			return nil, fmt.Errorf("invalid tag name %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		seen[name] = true
		tags = append(tags, tag{name: name, value: strings.Trim(value, " \t\r\n")})
	}
	return tags, nil
}

// validTagName: ALPHA *ALNUMPUNC (ALNUMPUNC = ALPHA / DIGIT / "_").
func validTagName(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// stripFWS removes folding whitespace, as allowed inside base64 values.
func stripFWS(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// splitList splits a colon-separated list, trimming whitespace and dropping
// empty elements.
func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ":") {
		if p = strings.Trim(p, " \t\r\n"); p != "" {
			out = append(out, p)
		}
	}
	return out
}
