// Package mtasts assesses SMTP MTA Strict Transport Security (RFC 8461):
// the _mta-sts TXT record, the HTTPS-hosted policy and its consistency with
// the domain's MX records.
package mtasts

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Modes.
const (
	ModeEnforce = "enforce"
	ModeTesting = "testing"
	ModeNone    = "none"
)

// MaxMaxAge is the largest max_age allowed by RFC 8461 (one year).
const MaxMaxAge = 31557600

// Record is a parsed _mta-sts TXT record.
type Record struct {
	Raw        string            `json:"raw"`
	ID         string            `json:"id"`
	Extensions map[string]string `json:"extensions,omitempty"`
}

// IsSTSRecord reports whether a TXT record claims to be an MTA-STS record.
func IsSTSRecord(txt string) bool {
	return strings.HasPrefix(txt, "v=STSv1;") || txt == "v=STSv1" || strings.HasPrefix(txt, "v=STSv1 ")
}

// ParseRecord parses an MTA-STS TXT record (RFC 8461 section 3.1).
func ParseRecord(txt string) (*Record, error) {
	if !IsSTSRecord(txt) {
		return nil, errors.New(`record must start with "v=STSv1;"`)
	}
	r := &Record{Raw: txt, Extensions: map[string]string{}}
	seen := map[string]bool{}
	for i, part := range strings.Split(txt, ";") {
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("malformed field %q", part)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		switch {
		case i == 0:
			// v=STSv1, checked above.
		case name == "id":
			if value == "" || len(value) > 32 || !isAlnum(value) {
				return nil, fmt.Errorf("id must be 1-32 letters and digits, got %q", value)
			}
			r.ID = value
		default:
			r.Extensions[name] = value
		}
	}
	if r.ID == "" {
		return nil, errors.New("required field id is missing")
	}
	return r, nil
}

func isAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Policy is a parsed MTA-STS policy file.
type Policy struct {
	Version string   `json:"version"`
	Mode    string   `json:"mode"`
	MaxAge  int      `json:"max_age"`
	MX      []string `json:"mx"`
	// LFOnly is set when lines end with LF instead of CRLF.
	LFOnly      bool     `json:"lf_line_endings,omitempty"`
	UnknownKeys []string `json:"unknown_keys,omitempty"`
}

// ParsePolicy parses a policy body (RFC 8461 section 3.2).
func ParsePolicy(body string) (*Policy, error) {
	p := &Policy{MaxAge: -1}
	p.LFOnly = strings.Contains(body, "\n") && !strings.Contains(body, "\r\n")
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %q is not a key: value pair", truncate(line, 60))
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "mx" && seen[key] {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		switch key {
		case "version":
			p.Version = value
		case "mode":
			p.Mode = value
		case "max_age":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > MaxMaxAge || len(value) > 10 {
				return nil, fmt.Errorf("max_age must be an integer between 0 and %d, got %q", MaxMaxAge, value)
			}
			p.MaxAge = n
		case "mx":
			if !validMXPattern(value) {
				return nil, fmt.Errorf("invalid mx pattern %q", value)
			}
			p.MX = append(p.MX, strings.ToLower(strings.TrimSuffix(value, ".")))
		default:
			p.UnknownKeys = append(p.UnknownKeys, key)
		}
	}
	switch {
	case p.Version != "STSv1":
		return nil, fmt.Errorf("version must be STSv1, got %q", p.Version)
	case p.Mode != ModeEnforce && p.Mode != ModeTesting && p.Mode != ModeNone:
		return nil, fmt.Errorf("mode must be enforce, testing or none, got %q", p.Mode)
	case p.MaxAge < 0:
		return nil, errors.New("required key max_age is missing")
	case len(p.MX) == 0 && p.Mode != ModeNone:
		return nil, errors.New("at least one mx pattern is required")
	}
	return p, nil
}

func validMXPattern(s string) bool {
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	if s == "" || strings.Contains(s, "*") || !strings.Contains(s, ".") {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Matches reports whether host matches an mx pattern. A wildcard matches
// exactly one left-most label (RFC 8461 section 4.1).
func Matches(pattern, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		label, rest, found := strings.Cut(host, ".")
		return found && label != "" && rest == suffix
	}
	return host == pattern
}

// Covers reports whether any pattern of the policy matches host.
func (p *Policy) Covers(host string) bool {
	for _, pat := range p.MX {
		if Matches(pat, host) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
