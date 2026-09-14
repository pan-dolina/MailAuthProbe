// Package findings defines the finding model shared by all assessments.
//
// A Finding is a single observation about a domain or message. Findings are
// instantiated from Rules, which live in a central catalog so that finding
// IDs remain stable between releases.
package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Severity ranks findings. The zero value is invalid.
type Severity int

// Severities in ascending order.
const (
	SeverityPass Severity = iota + 1
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityPass:     "pass",
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// Severities returns all severities from most to least severe.
func Severities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityPass}
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// Valid reports whether s is a defined severity.
func (s Severity) Valid() bool {
	_, ok := severityNames[s]
	return ok
}

// ParseSeverity parses a severity name case-insensitively.
func ParseSeverity(name string) (Severity, error) {
	for s, n := range severityNames {
		if strings.EqualFold(n, name) {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q", name)
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("invalid severity %d", int(s))
	}
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Category classifies the nature of a finding independently of its severity.
type Category string

// Categories.
const (
	// CategoryViolation: the configuration or message violates a standard.
	CategoryViolation Category = "standard-violation"
	// CategoryWeakness: standards-compliant but exploitable or ineffective.
	CategoryWeakness Category = "security-weakness"
	// CategoryHardening: an improvement beyond the minimum requirements.
	CategoryHardening Category = "hardening"
	// CategoryInformational: context that needs no action, including passes.
	CategoryInformational Category = "informational"
)

// Component identifies the subsystem a finding belongs to.
type Component string

// Components.
const (
	ComponentDNS         Component = "dns"
	ComponentMX          Component = "mx"
	ComponentSPF         Component = "spf"
	ComponentDKIM        Component = "dkim"
	ComponentDMARC       Component = "dmarc"
	ComponentMTASTS      Component = "mta-sts"
	ComponentTLSRPT      Component = "tls-rpt"
	ComponentMessage     Component = "message"
	ComponentReceived    Component = "received"
	ComponentAuthResults Component = "authentication-results"
	ComponentARC         Component = "arc"
)

// Rule is the static definition of a finding type.
type Rule struct {
	ID             string
	Component      Component
	Category       Category
	Severity       Severity
	Title          string
	Recommendation string
	References     []string
}

// Finding is a concrete observation.
type Finding struct {
	ID             string    `json:"id"`
	Severity       Severity  `json:"severity"`
	Category       Category  `json:"category"`
	Component      Component `json:"component"`
	Title          string    `json:"title"`
	Subject        string    `json:"subject,omitempty"`
	Description    string    `json:"description"`
	Evidence       []string  `json:"evidence,omitempty"`
	Recommendation string    `json:"recommendation,omitempty"`
	References     []string  `json:"references,omitempty"`
}

// New instantiates a finding from the rule. Subject names the object the
// finding is about (a domain, a DNS name, a signature); it may be empty.
func (r Rule) New(subject, description string, evidence ...string) Finding {
	return Finding{
		ID:             r.ID,
		Severity:       r.Severity,
		Category:       r.Category,
		Component:      r.Component,
		Title:          r.Title,
		Subject:        subject,
		Description:    description,
		Evidence:       slices.Clone(evidence),
		Recommendation: r.Recommendation,
		References:     slices.Clone(r.References),
	}
}

// WithSeverity returns a copy of f with a different severity. Rules define a
// default; context can make the same condition more or less severe.
func (f Finding) WithSeverity(s Severity) Finding {
	f.Severity = s
	return f
}

// WithEvidence returns a copy of f with additional evidence lines.
func (f Finding) WithEvidence(evidence ...string) Finding {
	f.Evidence = append(slices.Clone(f.Evidence), evidence...)
	return f
}

// Sort orders findings deterministically: most severe first, then by ID,
// subject, description and evidence.
func Sort(fs []Finding) {
	slices.SortStableFunc(fs, Compare)
}

// Compare implements the ordering used by Sort.
func Compare(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(b.Severity, a.Severity),
		cmp.Compare(a.ID, b.ID),
		cmp.Compare(a.Subject, b.Subject),
		cmp.Compare(a.Description, b.Description),
		slices.Compare(a.Evidence, b.Evidence),
	)
}

// Max returns the highest severity in fs, or 0 if fs is empty.
func Max(fs []Finding) Severity {
	var m Severity
	for _, f := range fs {
		m = max(m, f.Severity)
	}
	return m
}

// Counts tallies findings by severity name. All severities are present.
func Counts(fs []Finding) map[string]int {
	c := make(map[string]int, len(severityNames))
	for _, n := range severityNames {
		c[n] = 0
	}
	for _, f := range fs {
		c[f.Severity.String()]++
	}
	return c
}

// AtLeast returns the findings whose severity is >= threshold.
func AtLeast(fs []Finding, threshold Severity) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity >= threshold {
			out = append(out, f)
		}
	}
	return out
}
