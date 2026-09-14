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

// MX rules.
var (
	MXNone = register(Rule{
		ID:             "MAIL-MX-001",
		Component:      ComponentMX,
		Category:       CategoryHardening,
		Severity:       SeverityMedium,
		Title:          "No MX records; mail relies on implicit MX",
		Recommendation: "Publish explicit MX records for domains that receive mail, or a null MX (\"0 .\") for domains that do not.",
		References:     []string{RFC5321 + "#section-5.1", RFC7505},
	})
	MXNoMailHost = register(Rule{
		ID:             "MAIL-MX-002",
		Component:      ComponentMX,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "Domain publishes neither MX nor address records",
		Recommendation: "If the domain does not receive mail, publish a null MX record (\"0 .\") so senders fail fast instead of retrying.",
		References:     []string{RFC7505},
	})
	MXDomainNotFound = register(Rule{
		ID:             "MAIL-MX-003",
		Component:      ComponentMX,
		Category:       CategoryInformational,
		Severity:       SeverityHigh,
		Title:          "Domain does not exist",
		Recommendation: "Check the domain name. A non-existent domain cannot send or receive mail.",
		References:     []string{RFC1035},
	})
	MXNullMX = register(Rule{
		ID:         "MAIL-MX-004",
		Component:  ComponentMX,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Null MX published; domain does not accept mail",
		References: []string{RFC7505},
	})
	MXNullMixed = register(Rule{
		ID:             "MAIL-MX-005",
		Component:      ComponentMX,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "Null MX combined with other MX records",
		Recommendation: "Remove either the null MX record or the other MX records. A domain that publishes a null MX must not publish any other MX record.",
		References:     []string{RFC7505 + "#section-3"},
	})
	MXNullPreference = register(Rule{
		ID:             "MAIL-MX-006",
		Component:      ComponentMX,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Null MX uses a non-zero preference",
		Recommendation: "Publish the null MX with preference 0: \"MX 0 .\".",
		References:     []string{RFC7505 + "#section-3"},
	})
	MXDuplicateHost = register(Rule{
		ID:             "MAIL-MX-007",
		Component:      ComponentMX,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "Duplicate MX host",
		Recommendation: "List each mail exchanger once. Duplicates do not add redundancy and may indicate a copy-paste error.",
		References:     []string{RFC5321 + "#section-5.1"},
	})
	MXIPLiteral = register(Rule{
		ID:             "MAIL-MX-008",
		Component:      ComponentMX,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MX target is an IP address",
		Recommendation: "MX records must name a host. Create an A/AAAA record for the mail server and point the MX record at that name.",
		References:     []string{RFC5321 + "#section-5.1", RFC1035 + "#section-3.3.9"},
	})
	MXCNAME = register(Rule{
		ID:             "MAIL-MX-009",
		Component:      ComponentMX,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "MX target is a CNAME alias",
		Recommendation: "Point the MX record at the canonical host name that owns the A/AAAA records, not at an alias.",
		References:     []string{RFC2181 + "#section-10.3", RFC5321 + "#section-5.1"},
	})
	MXNoAddress = register(Rule{
		ID:             "MAIL-MX-010",
		Component:      ComponentMX,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "MX host has no address records",
		Recommendation: "Publish A and/or AAAA records for every MX host, or remove the MX record.",
		References:     []string{RFC5321 + "#section-5.1"},
	})
	MXNonPublicAddress = register(Rule{
		ID:             "MAIL-MX-011",
		Component:      ComponentMX,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MX host resolves to a non-routable address",
		Recommendation: "Publicly advertised MX hosts must resolve to globally routable addresses. Remove private, loopback or link-local addresses from public DNS.",
		References:     []string{"https://www.iana.org/assignments/iana-ipv4-special-registry/", "https://www.iana.org/assignments/iana-ipv6-special-registry/"},
	})
	MXLookupInconsistent = register(Rule{
		ID:             "MAIL-MX-012",
		Component:      ComponentMX,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "MX host lookup failed",
		Recommendation: "Address lookups for this MX host failed temporarily or returned a malformed response. Check the authoritative servers for the host's zone.",
		References:     []string{RFC1035},
	})
	MXIPv4Only = register(Rule{
		ID:         "MAIL-MX-013",
		Component:  ComponentMX,
		Category:   CategoryHardening,
		Severity:   SeverityInfo,
		Title:      "MX hosts are reachable over IPv4 only",
		References: []string{RFC5321 + "#section-5.1"},
	})
	MXSingleHost = register(Rule{
		ID:         "MAIL-MX-014",
		Component:  ComponentMX,
		Category:   CategoryHardening,
		Severity:   SeverityInfo,
		Title:      "Single MX host",
		References: []string{RFC5321 + "#section-5.1"},
	})
	MXValid = register(Rule{
		ID:        "MAIL-MX-015",
		Component: ComponentMX,
		Category:  CategoryInformational,
		Severity:  SeverityPass,
		Title:     "MX records are valid",
	})
	MXInvalidHostname = register(Rule{
		ID:             "MAIL-MX-016",
		Component:      ComponentMX,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MX target is not a valid host name",
		Recommendation: "MX targets must be host names made of letters, digits and hyphens.",
		References:     []string{RFC5321 + "#section-2.3.5", RFC1035 + "#section-2.3.1"},
	})
	MXTooMany = register(Rule{
		ID:         "MAIL-MX-017",
		Component:  ComponentMX,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Too many MX hosts to check",
		References: []string{RFC5321 + "#section-5.1"},
	})
)
