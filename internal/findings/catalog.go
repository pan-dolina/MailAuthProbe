package findings

import (
	"slices"
	"strings"
)

// The catalog holds every rule known to MailAuthProbe. Rule IDs are a public
// interface: they are never renumbered or reused. A rule that is no longer
// emitted stays in the catalog with a "Deprecated:" title prefix.

var catalog = map[string]Rule{}

func register(r Rule) Rule {
	if _, dup := catalog[r.ID]; dup {
		panic("findings: duplicate rule ID " + r.ID)
	}
	catalog[r.ID] = r
	return r
}

// Lookup returns the rule with the given ID.
func Lookup(id string) (Rule, bool) {
	r, ok := catalog[id]
	return r, ok
}

// Rules returns all rules ordered by ID.
func Rules() []Rule {
	out := make([]Rule, 0, len(catalog))
	for _, r := range catalog {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Reference URLs used across rules.
const (
	RFC1035 = "https://www.rfc-editor.org/rfc/rfc1035"
	RFC2181 = "https://www.rfc-editor.org/rfc/rfc2181"
	RFC5321 = "https://www.rfc-editor.org/rfc/rfc5321"
	RFC5322 = "https://www.rfc-editor.org/rfc/rfc5322"
	RFC6376 = "https://www.rfc-editor.org/rfc/rfc6376"
	RFC7208 = "https://www.rfc-editor.org/rfc/rfc7208"
	RFC7489 = "https://www.rfc-editor.org/rfc/rfc7489"
	RFC7505 = "https://www.rfc-editor.org/rfc/rfc7505"
	RFC8301 = "https://www.rfc-editor.org/rfc/rfc8301"
	RFC8460 = "https://www.rfc-editor.org/rfc/rfc8460"
	RFC8461 = "https://www.rfc-editor.org/rfc/rfc8461"
	RFC8463 = "https://www.rfc-editor.org/rfc/rfc8463"
	RFC8601 = "https://www.rfc-editor.org/rfc/rfc8601"
	RFC8617 = "https://www.rfc-editor.org/rfc/rfc8617"
	RFC2045 = "https://www.rfc-editor.org/rfc/rfc2045"
	RFC2046 = "https://www.rfc-editor.org/rfc/rfc2046"
)

// DNS rules.
var (
	DNSLookupFailed = register(Rule{
		ID:             "MAIL-DNS-001",
		Component:      ComponentDNS,
		Category:       CategoryInformational,
		Severity:       SeverityHigh,
		Title:          "DNS lookup failed",
		Recommendation: "Retry the scan. If the failure persists, check the authoritative name servers for the zone and the resolver passed with --resolver.",
		References:     []string{RFC1035},
	})
	DNSQueryBudgetExceeded = register(Rule{
		ID:             "MAIL-DNS-002",
		Component:      ComponentDNS,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "DNS query budget exhausted",
		Recommendation: "The scan stopped issuing DNS queries to protect the resolver. Results for the affected checks are incomplete.",
	})
)
