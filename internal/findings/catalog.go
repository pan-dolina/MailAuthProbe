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

// SPF rules.
var (
	SPFMissing = register(Rule{
		ID:             "MAIL-SPF-001",
		Component:      ComponentSPF,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "No SPF record",
		Recommendation: "Publish an SPF record listing the hosts allowed to send for the domain. Domains that never send mail should publish \"v=spf1 -all\".",
		References:     []string{RFC7208 + "#section-4.5"},
	})
	SPFMultiple = register(Rule{
		ID:             "MAIL-SPF-002",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "Multiple SPF records",
		Recommendation: "Merge all SPF policies into a single TXT record. With more than one record every SPF check returns permerror.",
		References:     []string{RFC7208 + "#section-4.5"},
	})
	SPFSyntax = register(Rule{
		ID:             "MAIL-SPF-003",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "SPF syntax error",
		Recommendation: "Fix the invalid terms. Any syntax error makes the whole record evaluate to permerror.",
		References:     []string{RFC7208 + "#section-4.6", RFC7208 + "#section-12"},
	})
	SPFLoop = register(Rule{
		ID:             "MAIL-SPF-004",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "SPF include or redirect loop",
		Recommendation: "Break the cycle in the include/redirect chain. Receivers stop at the lookup limit and return permerror.",
		References:     []string{RFC7208 + "#section-4.6.4"},
	})
	SPFLookupLimit = register(Rule{
		ID:             "MAIL-SPF-005",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "SPF exceeds the 10 DNS lookup limit",
		Recommendation: "Reduce include, a, mx, ptr, exists and redirect terms: replace stable hosts with ip4/ip6 ranges and remove unused includes. Receivers return permerror once the limit is exceeded.",
		References:     []string{RFC7208 + "#section-4.6.4"},
	})
	SPFVoidLimit = register(Rule{
		ID:             "MAIL-SPF-006",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "SPF exceeds the void lookup limit",
		Recommendation: "Remove mechanisms that reference names without records. More than two void lookups lead to permerror at many receivers.",
		References:     []string{RFC7208 + "#section-4.6.4"},
	})
	SPFPassAll = register(Rule{
		ID:             "MAIL-SPF-007",
		Component:      ComponentSPF,
		Category:       CategoryWeakness,
		Severity:       SeverityCritical,
		Title:          "SPF authorizes every host (+all)",
		Recommendation: "Replace \"+all\" with \"-all\" or \"~all\". \"+all\" lets anyone on the Internet pass SPF for the domain.",
		References:     []string{RFC7208 + "#section-5.1"},
	})
	SPFNeutralAll = register(Rule{
		ID:             "MAIL-SPF-008",
		Component:      ComponentSPF,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "SPF ends with ?all (neutral)",
		Recommendation: "Use \"-all\" (or \"~all\" while monitoring) so that unauthorized hosts are not treated like unknown ones.",
		References:     []string{RFC7208 + "#section-8.2"},
	})
	SPFSoftFailAll = register(Rule{
		ID:             "MAIL-SPF-009",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF ends with ~all (softfail)",
		Recommendation: "Once all legitimate senders are covered, consider \"-all\". With an enforcing DMARC policy \"~all\" is an acceptable choice.",
		References:     []string{RFC7208 + "#section-8.5"},
	})
	SPFNoAll = register(Rule{
		ID:             "MAIL-SPF-010",
		Component:      ComponentSPF,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "SPF has no all mechanism or redirect",
		Recommendation: "End the record with \"-all\" or \"~all\". Without it, unmatched hosts get the default neutral result.",
		References:     []string{RFC7208 + "#section-4.7"},
	})
	SPFBroadRange = register(Rule{
		ID:             "MAIL-SPF-011",
		Component:      ComponentSPF,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "SPF authorizes a very large address range",
		Recommendation: "Authorize only the addresses that actually send mail. Large ranges let unrelated hosts (other customers of the same network) pass SPF.",
		References:     []string{RFC7208 + "#section-5.6"},
	})
	SPFPTR = register(Rule{
		ID:             "MAIL-SPF-012",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF uses the deprecated ptr mechanism",
		Recommendation: "Replace \"ptr\" with ip4/ip6 or a mechanisms. \"ptr\" is slow, unreliable and should not be published.",
		References:     []string{RFC7208 + "#section-5.5"},
	})
	SPFIncludeNoRecord = register(Rule{
		ID:             "MAIL-SPF-013",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "SPF include or redirect target has no SPF record",
		Recommendation: "Remove the include/redirect or fix the target. An include of a domain without SPF evaluates to permerror.",
		References:     []string{RFC7208 + "#section-5.2", RFC7208 + "#section-6.1"},
	})
	SPFTempError = register(Rule{
		ID:             "MAIL-SPF-014",
		Component:      ComponentSPF,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "SPF lookup failed temporarily",
		Recommendation: "A DNS lookup needed for SPF failed. Receivers would return temperror; check the name servers of the affected zone.",
		References:     []string{RFC7208 + "#section-2.6.6"},
	})
	SPFTermsAfterAll = register(Rule{
		ID:             "MAIL-SPF-015",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF terms after all are never evaluated",
		Recommendation: "Move the mechanisms before \"all\" or remove them.",
		References:     []string{RFC7208 + "#section-5.1"},
	})
	SPFRedirectIgnored = register(Rule{
		ID:             "MAIL-SPF-016",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF redirect is ignored because the record contains all",
		Recommendation: "Remove either the redirect modifier or the all mechanism.",
		References:     []string{RFC7208 + "#section-6.1"},
	})
	SPFLookupsNearLimit = register(Rule{
		ID:             "MAIL-SPF-017",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF is close to the 10 DNS lookup limit",
		Recommendation: "A provider adding a single include to its own record will push the domain over the limit. Flatten or remove includes where possible.",
		References:     []string{RFC7208 + "#section-4.6.4"},
	})
	SPFPMacro = register(Rule{
		ID:             "MAIL-SPF-018",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF uses the discouraged p macro",
		Recommendation: "Avoid the \"p\" macro; it requires reverse lookups and should not be used.",
		References:     []string{RFC7208 + "#section-7.3"},
	})
	SPFExp = register(Rule{
		ID:         "MAIL-SPF-019",
		Component:  ComponentSPF,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "SPF publishes an explanation (exp)",
		References: []string{RFC7208 + "#section-6.2"},
	})
	SPFUnknownModifier = register(Rule{
		ID:         "MAIL-SPF-020",
		Component:  ComponentSPF,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "SPF contains an unknown modifier",
		References: []string{RFC7208 + "#section-6"},
	})
	SPFMXLimit = register(Rule{
		ID:             "MAIL-SPF-021",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "SPF mx mechanism references more than 10 MX records",
		Recommendation: "Use ip4/ip6 for the mail servers instead of \"mx\", or reduce the number of MX records.",
		References:     []string{RFC7208 + "#section-4.6.4"},
	})
	SPFValid = register(Rule{
		ID:        "MAIL-SPF-022",
		Component: ComponentSPF,
		Category:  CategoryInformational,
		Severity:  SeverityPass,
		Title:     "SPF record is valid",
	})
	SPFDynamic = register(Rule{
		ID:         "MAIL-SPF-023",
		Component:  ComponentSPF,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "SPF term depends on message data and cannot be followed statically",
		References: []string{RFC7208 + "#section-7"},
	})
	SPFRecordTooLong = register(Rule{
		ID:             "MAIL-SPF-024",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF record is longer than 450 octets",
		Recommendation: "Keep SPF records short so that the DNS response fits in 512 octets; long records force TCP fallback and fail with some resolvers.",
		References:     []string{RFC7208 + "#section-3.4"},
	})
	SPFVoidTarget = register(Rule{
		ID:             "MAIL-SPF-025",
		Component:      ComponentSPF,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "SPF mechanism references a name without records",
		Recommendation: "Remove mechanisms whose target has no address or MX records; they add a void lookup and never match.",
		References:     []string{RFC7208 + "#section-4.6.4"},
	})
)

// DMARC rules.
var (
	DMARCMissing = register(Rule{
		ID:             "MAIL-DMARC-001",
		Component:      ComponentDMARC,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "No DMARC record",
		Recommendation: "Publish a DMARC record at _dmarc.<domain>, starting with \"v=DMARC1; p=none; rua=mailto:...\" to collect reports, then move to quarantine or reject.",
		References:     []string{RFC7489 + "#section-6.1"},
	})
	DMARCMultiple = register(Rule{
		ID:             "MAIL-DMARC-002",
		Component:      ComponentDMARC,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "Multiple DMARC records",
		Recommendation: "Keep exactly one DMARC record. With several records receivers do not apply DMARC at all.",
		References:     []string{RFC7489 + "#section-6.6.3"},
	})
	DMARCInvalid = register(Rule{
		ID:             "MAIL-DMARC-003",
		Component:      ComponentDMARC,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "Invalid DMARC record",
		Recommendation: "Fix the record so that it starts with \"v=DMARC1\" and contains a valid p tag. Receivers ignore invalid records.",
		References:     []string{RFC7489 + "#section-6.3", RFC7489 + "#section-6.6.3"},
	})
	DMARCPolicyNone = register(Rule{
		ID:             "MAIL-DMARC-004",
		Component:      ComponentDMARC,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "DMARC policy is p=none (monitoring only)",
		Recommendation: "After reviewing aggregate reports, move to p=quarantine and then p=reject so that spoofed mail is not delivered.",
		References:     []string{RFC7489 + "#section-6.3"},
	})
	DMARCPolicyQuarantine = register(Rule{
		ID:             "MAIL-DMARC-005",
		Component:      ComponentDMARC,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "DMARC policy is p=quarantine",
		Recommendation: "Consider p=reject once no legitimate mail is quarantined.",
		References:     []string{RFC7489 + "#section-6.3"},
	})
	DMARCPartialPct = register(Rule{
		ID:             "MAIL-DMARC-006",
		Component:      ComponentDMARC,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "DMARC policy applies to only part of the mail (pct < 100)",
		Recommendation: "Increase pct to 100. Messages outside the sampled percentage are handled with the next weaker policy.",
		References:     []string{RFC7489 + "#section-6.3"},
	})
	DMARCWeakSubdomainPolicy = register(Rule{
		ID:             "MAIL-DMARC-007",
		Component:      ComponentDMARC,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "DMARC subdomain policy is weaker than the domain policy",
		Recommendation: "Set sp to the same value as p unless specific subdomains still need monitoring; attackers can spoof arbitrary subdomains otherwise.",
		References:     []string{RFC7489 + "#section-6.3"},
	})
	DMARCNoRUA = register(Rule{
		ID:             "MAIL-DMARC-008",
		Component:      ComponentDMARC,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "DMARC aggregate reports are not requested",
		Recommendation: "Add rua=mailto:... to receive aggregate reports; without them you cannot see who sends mail using the domain.",
		References:     []string{RFC7489 + "#section-7.2"},
	})
	DMARCRUF = register(Rule{
		ID:         "MAIL-DMARC-009",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DMARC failure reports (ruf) requested",
		References: []string{RFC7489 + "#section-7.3"},
	})
	DMARCInvalidValue = register(Rule{
		ID:             "MAIL-DMARC-010",
		Component:      ComponentDMARC,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "DMARC tag has an invalid value",
		Recommendation: "Correct the tag value; receivers fall back to the default, which may not be what you intended.",
		References:     []string{RFC7489 + "#section-6.3"},
	})
	DMARCDuplicateTag = register(Rule{
		ID:             "MAIL-DMARC-011",
		Component:      ComponentDMARC,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "DMARC tag appears more than once",
		Recommendation: "Remove the duplicate tag. Receivers disagree on which occurrence wins.",
		References:     []string{RFC7489 + "#section-6.4"},
	})
	DMARCUnknownTag = register(Rule{
		ID:         "MAIL-DMARC-012",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DMARC record contains an unknown tag",
		References: []string{RFC7489 + "#section-6.3"},
	})
	DMARCInvalidURI = register(Rule{
		ID:             "MAIL-DMARC-013",
		Component:      ComponentDMARC,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "DMARC report URI is invalid",
		Recommendation: "Use URIs of the form mailto:dmarc-reports@example.com, optionally followed by a size limit such as !10m.",
		References:     []string{RFC7489 + "#section-6.2"},
	})
	DMARCExternalUnauthorized = register(Rule{
		ID:             "MAIL-DMARC-014",
		Component:      ComponentDMARC,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "External DMARC report destination is not authorized",
		Recommendation: "The receiving domain must publish \"v=DMARC1\" at <policy-domain>._report._dmarc.<destination-domain>; otherwise reports are not sent there.",
		References:     []string{RFC7489 + "#section-7.1"},
	})
	DMARCInherited = register(Rule{
		ID:         "MAIL-DMARC-015",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DMARC policy inherited from the organizational domain",
		References: []string{RFC7489 + "#section-6.6.3"},
	})
	DMARCStrictAlignment = register(Rule{
		ID:         "MAIL-DMARC-016",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DMARC requires strict identifier alignment",
		References: []string{RFC7489 + "#section-3.1"},
	})
	DMARCEnforced = register(Rule{
		ID:        "MAIL-DMARC-017",
		Component: ComponentDMARC,
		Category:  CategoryInformational,
		Severity:  SeverityPass,
		Title:     "DMARC policy is enforced",
	})
	DMARCFONoRUF = register(Rule{
		ID:         "MAIL-DMARC-018",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DMARC fo tag has no effect without ruf",
		References: []string{RFC7489 + "#section-6.3"},
	})
)

// DKIM rules.
var (
	DKIMNoSelector = register(Rule{
		ID:         "MAIL-DKIM-001",
		Component:  ComponentDKIM,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DKIM audit incomplete: no selector specified",
		References: []string{RFC6376 + "#section-3.1"},
	})
	DKIMKeyNotFound = register(Rule{
		ID:             "MAIL-DKIM-002",
		Component:      ComponentDKIM,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "DKIM key record not found",
		Recommendation: "Publish the public key at <selector>._domainkey.<domain>, or check that the selector name is correct.",
		References:     []string{RFC6376 + "#section-3.6.2"},
	})
	DKIMInvalidKey = register(Rule{
		ID:             "MAIL-DKIM-003",
		Component:      ComponentDKIM,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "DKIM key record is invalid",
		Recommendation: "Republish the key record as \"v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo>\". An invalid record makes every signature fail.",
		References:     []string{RFC6376 + "#section-3.6.1"},
	})
	DKIMKeyRevoked = register(Rule{
		ID:             "MAIL-DKIM-004",
		Component:      ComponentDKIM,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "DKIM key is revoked",
		Recommendation: "If this selector is still used for signing, publish the current public key. If it was retired deliberately, stop signing with it.",
		References:     []string{RFC6376 + "#section-3.6.1"},
	})
	DKIMKeyTooShort = register(Rule{
		ID:             "MAIL-DKIM-005",
		Component:      ComponentDKIM,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "DKIM RSA key shorter than 1024 bits",
		Recommendation: "Generate a new 2048-bit RSA key, publish it under a new selector and switch signing to it.",
		References:     []string{RFC8301 + "#section-3.2"},
	})
	DKIMKeyWeak = register(Rule{
		ID:             "MAIL-DKIM-006",
		Component:      ComponentDKIM,
		Category:       CategoryHardening,
		Severity:       SeverityMedium,
		Title:          "DKIM RSA key shorter than 2048 bits",
		Recommendation: "Rotate to a 2048-bit RSA key; 1024-bit keys are below current recommendations.",
		References:     []string{RFC8301 + "#section-3.2"},
	})
	DKIMKeyTooLong = register(Rule{
		ID:             "MAIL-DKIM-007",
		Component:      ComponentDKIM,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "DKIM RSA key longer than 4096 bits",
		Recommendation: "Use a 2048- or 4096-bit key; longer keys may exceed verifier limits and DNS response sizes.",
		References:     []string{RFC8301 + "#section-3.2"},
	})
	DKIMKeySHA1Only = register(Rule{
		ID:             "MAIL-DKIM-008",
		Component:      ComponentDKIM,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "DKIM key restricts hashes to SHA-1",
		Recommendation: "Remove the h= tag or set h=sha256.",
		References:     []string{RFC8301 + "#section-3.1"},
	})
	DKIMKeyTesting = register(Rule{
		ID:             "MAIL-DKIM-009",
		Component:      ComponentDKIM,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "DKIM key is in testing mode (t=y)",
		Recommendation: "Remove t=y once signing is verified to work.",
		References:     []string{RFC6376 + "#section-3.6.1"},
	})
	DKIMKeyServiceMismatch = register(Rule{
		ID:             "MAIL-DKIM-010",
		Component:      ComponentDKIM,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "DKIM key is not usable for e-mail",
		Recommendation: "Remove the s= tag or include \"email\" in it.",
		References:     []string{RFC6376 + "#section-3.6.1"},
	})
	DKIMKeyEd25519 = register(Rule{
		ID:         "MAIL-DKIM-011",
		Component:  ComponentDKIM,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DKIM key uses Ed25519",
		References: []string{RFC8463},
	})
	DKIMKeyValid = register(Rule{
		ID:        "MAIL-DKIM-012",
		Component: ComponentDKIM,
		Category:  CategoryInformational,
		Severity:  SeverityPass,
		Title:     "DKIM key record is valid",
	})
	DKIMMultipleKeys = register(Rule{
		ID:             "MAIL-DKIM-013",
		Component:      ComponentDKIM,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Multiple TXT records at a DKIM selector",
		Recommendation: "Publish exactly one key record per selector.",
		References:     []string{RFC6376 + "#section-3.6.2.2"},
	})
	DKIMKeyUnknownTag = register(Rule{
		ID:         "MAIL-DKIM-014",
		Component:  ComponentDKIM,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DKIM key record contains an unknown tag",
		References: []string{RFC6376 + "#section-3.6.1"},
	})
	DKIMKeyPKCS1 = register(Rule{
		ID:             "MAIL-DKIM-015",
		Component:      ComponentDKIM,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "DKIM RSA key is not in SubjectPublicKeyInfo format",
		Recommendation: "Publish the key as a DER SubjectPublicKeyInfo (the output of \"openssl rsa -pubout -outform DER\").",
		References:     []string{RFC6376 + "#section-3.6.1"},
	})
)

// Received chain rules.
var (
	RcvdNone = register(Rule{
		ID:             "MAIL-RCVD-001",
		Component:      ComponentReceived,
		Category:       CategoryInformational,
		Severity:       SeverityLow,
		Title:          "No Received headers",
		Recommendation: "Analyse the message as delivered to a mailbox (with full headers) to see its transport path.",
		References:     []string{RFC5321 + "#section-4.4"},
	})
	RcvdUnparseable = register(Rule{
		ID:             "MAIL-RCVD-002",
		Component:      ComponentReceived,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Received header could not be parsed",
		Recommendation: "Treat data from this hop with caution; malformed trace headers are common in forged or badly generated messages.",
		References:     []string{RFC5321 + "#section-4.4"},
	})
	RcvdTimeTravel = register(Rule{
		ID:             "MAIL-RCVD-003",
		Component:      ComponentReceived,
		Category:       CategoryInformational,
		Severity:       SeverityLow,
		Title:          "Received timestamps go backwards",
		Recommendation: "Headers below the inconsistency may have been added by the sender rather than by the servers they name.",
		References:     []string{RFC5321 + "#section-4.4"},
	})
	RcvdTooMany = register(Rule{
		ID:             "MAIL-RCVD-004",
		Component:      ComponentReceived,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "Too many Received headers",
		Recommendation: "Check for a mail loop or for headers padded by the sender to hide the real origin.",
		References:     []string{RFC5321 + "#section-6.3"},
	})
	RcvdNoTLS = register(Rule{
		ID:         "MAIL-RCVD-005",
		Component:  ComponentReceived,
		Category:   CategoryHardening,
		Severity:   SeverityInfo,
		Title:      "Hop transmitted without TLS",
		References: []string{"https://www.rfc-editor.org/rfc/rfc3848"},
	})
	RcvdNoDate = register(Rule{
		ID:             "MAIL-RCVD-006",
		Component:      ComponentReceived,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Received header has no date",
		Recommendation: "Every Received header must end with \"; date-time\". A missing date suggests a forged or broken header.",
		References:     []string{RFC5321 + "#section-4.4"},
	})
	RcvdDelay = register(Rule{
		ID:         "MAIL-RCVD-007",
		Component:  ComponentReceived,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Long delay between hops",
		References: []string{RFC5321 + "#section-4.4"},
	})
)

// SPF message verification rules.
var (
	SPFMessagePass = register(Rule{
		ID:         "MAIL-SPF-030",
		Component:  ComponentSPF,
		Category:   CategoryInformational,
		Severity:   SeverityPass,
		Title:      "SPF pass",
		References: []string{RFC7208 + "#section-2.6.3"},
	})
	SPFMessageFail = register(Rule{
		ID:             "MAIL-SPF-031",
		Component:      ComponentSPF,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "SPF fail: sending host is not authorized",
		Recommendation: "The client is explicitly not authorized to send for this domain. Unless the message was forwarded, treat it as spoofed.",
		References:     []string{RFC7208 + "#section-2.6.2"},
	})
	SPFMessageSoftFail = register(Rule{
		ID:             "MAIL-SPF-032",
		Component:      ComponentSPF,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "SPF softfail: sending host is probably not authorized",
		Recommendation: "The domain owner believes this host is not authorized. Check DKIM and DMARC before trusting the message.",
		References:     []string{RFC7208 + "#section-2.6.5"},
	})
	SPFMessageNeutral = register(Rule{
		ID:             "MAIL-SPF-033",
		Component:      ComponentSPF,
		Category:       CategoryInformational,
		Severity:       SeverityLow,
		Title:          "SPF neutral or none: sender not verified",
		Recommendation: "SPF gives no assurance for this message; rely on DKIM and DMARC.",
		References:     []string{RFC7208 + "#section-2.6.1"},
	})
	SPFMessageError = register(Rule{
		ID:             "MAIL-SPF-034",
		Component:      ComponentSPF,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "SPF evaluation error",
		Recommendation: "SPF returned temperror or permerror; receivers may reject or ignore SPF for this domain. See the reason for details.",
		References:     []string{RFC7208 + "#section-2.6.6", RFC7208 + "#section-2.6.7"},
	})
	SPFInputsInferred = register(Rule{
		ID:         "MAIL-SPF-035",
		Component:  ComponentSPF,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "SPF inputs inferred from message headers",
		References: []string{RFC7208 + "#section-9.1"},
	})
	SPFNotEvaluated = register(Rule{
		ID:         "MAIL-SPF-036",
		Component:  ComponentSPF,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "SPF not evaluated",
		References: []string{RFC7208 + "#section-4.1"},
	})
)

// DMARC message evaluation rules.
var (
	DMARCMessagePass = register(Rule{
		ID:         "MAIL-DMARC-030",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityPass,
		Title:      "DMARC pass",
		References: []string{RFC7489 + "#section-4.2"},
	})
	DMARCMessageFail = register(Rule{
		ID:             "MAIL-DMARC-031",
		Component:      ComponentDMARC,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "DMARC fail",
		Recommendation: "The From domain could not be authenticated. Unless the message passed through a forwarder or mailing list that broke authentication, treat it as spoofed.",
		References:     []string{RFC7489 + "#section-6.6.2"},
	})
	DMARCMessageNoPolicy = register(Rule{
		ID:             "MAIL-DMARC-032",
		Component:      ComponentDMARC,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "No usable DMARC policy for the From domain",
		Recommendation: "Without DMARC, receivers have no instruction to reject mail that spoofs this From domain.",
		References:     []string{RFC7489 + "#section-6.6.3"},
	})
	DMARCMessageBadFrom = register(Rule{
		ID:             "MAIL-DMARC-033",
		Component:      ComponentDMARC,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "From header unusable for DMARC",
		Recommendation: "A message must have exactly one From header with one mailbox. Multiple or malformed From headers are a common spoofing technique.",
		References:     []string{RFC7489 + "#section-6.6.1", RFC5322 + "#section-3.6"},
	})
	DMARCMessageTempError = register(Rule{
		ID:             "MAIL-DMARC-034",
		Component:      ComponentDMARC,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "DMARC temperror",
		Recommendation: "The DMARC policy could not be retrieved. Retry the analysis.",
		References:     []string{RFC7489 + "#section-6.6.3"},
	})
	DMARCMessageStrictMisalign = register(Rule{
		ID:             "MAIL-DMARC-035",
		Component:      ComponentDMARC,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "Strict alignment prevented a DMARC pass",
		Recommendation: "An authenticated identifier from the same organization failed strict alignment. If the domain owner intends subdomains to send, relaxed alignment (adkim=r / aspf=r) would pass.",
		References:     []string{RFC7489 + "#section-3.1"},
	})
	DMARCMessageSPFUnaligned = register(Rule{
		ID:         "MAIL-DMARC-036",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "SPF passed but is not aligned with From",
		References: []string{RFC7489 + "#section-3.1.2"},
	})
	DMARCMessageIndeterminate = register(Rule{
		ID:             "MAIL-DMARC-038",
		Component:      ComponentDMARC,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "DMARC result indeterminate",
		Recommendation: "Provide the missing inputs (--source-ip, --helo, --mail-from, or the complete message including its body) to obtain a definite DMARC result.",
		References:     []string{RFC7489 + "#section-6.6.2"},
	})
	DMARCMessageDKIMUnaligned = register(Rule{
		ID:         "MAIL-DMARC-037",
		Component:  ComponentDMARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DKIM passed but is not aligned with From",
		References: []string{RFC7489 + "#section-3.1.1"},
	})
)

// Authentication-Results comparison rules.
var (
	ARConflict = register(Rule{
		ID:             "MAIL-AR-001",
		Component:      ComponentAuthResults,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "Conflicting Authentication-Results from the same server",
		Recommendation: "Two headers claim to come from the same authserv-id but disagree. One of them was probably added by the sender to mislead filters or users; trust only headers your own receiving MTA adds and strips.",
		References:     []string{RFC8601 + "#section-5"},
	})
	ARMismatch = register(Rule{
		ID:             "MAIL-AR-002",
		Component:      ComponentAuthResults,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "Authentication-Results disagree with independent verification",
		Recommendation: "Differences can come from forged headers, message modification after delivery, DNS changes since receipt, or inferred SPF inputs. Investigate before relying on either verdict.",
		References:     []string{RFC8601 + "#section-7"},
	})
	ARConsistent = register(Rule{
		ID:        "MAIL-AR-003",
		Component: ComponentAuthResults,
		Category:  CategoryInformational,
		Severity:  SeverityPass,
		Title:     "Authentication-Results agree with independent verification",
	})
	ARUnparseable = register(Rule{
		ID:             "MAIL-AR-004",
		Component:      ComponentAuthResults,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Authentication-Results header cannot be parsed",
		Recommendation: "The header does not follow RFC 8601; it was not used for comparison.",
		References:     []string{RFC8601 + "#section-2.2"},
	})
	ARNone = register(Rule{
		ID:         "MAIL-AR-005",
		Component:  ComponentAuthResults,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "No Authentication-Results headers",
		References: []string{RFC8601},
	})
)

// MTA-STS rules.
var (
	MTASTSMissing = register(Rule{
		ID:             "MAIL-MTASTS-001",
		Component:      ComponentMTASTS,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "MTA-STS not deployed",
		Recommendation: "Publish an MTA-STS policy (start with mode: testing and TLS-RPT) so that senders require authenticated TLS when delivering to your MX hosts.",
		References:     []string{RFC8461},
	})
	MTASTSInvalidRecord = register(Rule{
		ID:             "MAIL-MTASTS-002",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "Invalid MTA-STS TXT record",
		Recommendation: "Publish exactly one record of the form \"v=STSv1; id=20260914T000000;\" at _mta-sts.<domain>.",
		References:     []string{RFC8461 + "#section-3.1"},
	})
	MTASTSFetchFailed = register(Rule{
		ID:             "MAIL-MTASTS-003",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MTA-STS policy cannot be fetched",
		Recommendation: "Serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with HTTP 200, or remove the TXT record.",
		References:     []string{RFC8461 + "#section-3.3"},
	})
	MTASTSCertificate = register(Rule{
		ID:             "MAIL-MTASTS-004",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MTA-STS policy host certificate is invalid",
		Recommendation: "Install a publicly trusted certificate valid for mta-sts.<domain>. Senders discard policies fetched over an invalid certificate.",
		References:     []string{RFC8461 + "#section-3.3"},
	})
	MTASTSRedirect = register(Rule{
		ID:             "MAIL-MTASTS-005",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MTA-STS policy URL redirects",
		Recommendation: "Serve the policy directly; senders must not follow HTTP redirects when fetching MTA-STS policies.",
		References:     []string{RFC8461 + "#section-3.3"},
	})
	MTASTSContentType = register(Rule{
		ID:             "MAIL-MTASTS-006",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "MTA-STS policy is not served as text/plain",
		Recommendation: "Configure the web server to return Content-Type: text/plain for mta-sts.txt.",
		References:     []string{RFC8461 + "#section-3.2"},
	})
	MTASTSInvalidPolicy = register(Rule{
		ID:             "MAIL-MTASTS-007",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MTA-STS policy is invalid",
		Recommendation: "The policy needs version: STSv1, mode (enforce, testing or none), max_age and at least one mx line.",
		References:     []string{RFC8461 + "#section-3.2"},
	})
	MTASTSTesting = register(Rule{
		ID:             "MAIL-MTASTS-008",
		Component:      ComponentMTASTS,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "MTA-STS policy in testing mode",
		Recommendation: "After TLS-RPT reports show no failures, switch to mode: enforce.",
		References:     []string{RFC8461 + "#section-5"},
	})
	MTASTSModeNone = register(Rule{
		ID:             "MAIL-MTASTS-009",
		Component:      ComponentMTASTS,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "MTA-STS policy mode is none",
		Recommendation: "mode: none is meant for retiring MTA-STS. Use testing or enforce to protect inbound mail.",
		References:     []string{RFC8461 + "#section-8.3"},
	})
	MTASTSShortMaxAge = register(Rule{
		ID:             "MAIL-MTASTS-010",
		Component:      ComponentMTASTS,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "MTA-STS max_age shorter than one day",
		Recommendation: "Use a max_age of weeks (for example 1209600) once the policy is stable.",
		References:     []string{RFC8461 + "#section-3.2"},
	})
	MTASTSMXMismatch = register(Rule{
		ID:             "MAIL-MTASTS-011",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityHigh,
		Title:          "MX hosts not covered by the MTA-STS policy",
		Recommendation: "Add mx lines for every MX host. In enforce mode senders refuse to deliver to hosts that do not match the policy.",
		References:     []string{RFC8461 + "#section-4.1"},
	})
	MTASTSCertExpiring = register(Rule{
		ID:             "MAIL-MTASTS-012",
		Component:      ComponentMTASTS,
		Category:       CategoryInformational,
		Severity:       SeverityLow,
		Title:          "MTA-STS policy host certificate expires soon",
		Recommendation: "Renew the certificate for mta-sts.<domain> before it expires.",
		References:     []string{RFC8461 + "#section-3.3"},
	})
	MTASTSPolicyWithoutRecord = register(Rule{
		ID:             "MAIL-MTASTS-013",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "MTA-STS policy published without a TXT record",
		Recommendation: "Publish the _mta-sts TXT record; without it the policy is never used.",
		References:     []string{RFC8461 + "#section-3.1"},
	})
	MTASTSValid = register(Rule{
		ID:        "MAIL-MTASTS-014",
		Component: ComponentMTASTS,
		Category:  CategoryInformational,
		Severity:  SeverityPass,
		Title:     "MTA-STS is enforced",
	})
	MTASTSLineEndings = register(Rule{
		ID:         "MAIL-MTASTS-015",
		Component:  ComponentMTASTS,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "MTA-STS policy uses LF line endings",
		References: []string{RFC8461 + "#section-3.2"},
	})
	MTASTSPolicyTooLarge = register(Rule{
		ID:             "MAIL-MTASTS-016",
		Component:      ComponentMTASTS,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "MTA-STS policy is too large",
		Recommendation: "Keep the policy to the defined keys; senders may refuse large policies.",
		References:     []string{RFC8461 + "#section-3.2"},
	})
)

// TLS-RPT rules.
var (
	TLSRPTMissing = register(Rule{
		ID:             "MAIL-TLSRPT-001",
		Component:      ComponentTLSRPT,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "TLS-RPT not configured",
		Recommendation: "Publish \"v=TLSRPTv1; rua=mailto:tls-reports@<domain>\" at _smtp._tls.<domain> to receive reports about failed TLS connections.",
		References:     []string{RFC8460 + "#section-3"},
	})
	TLSRPTInvalid = register(Rule{
		ID:             "MAIL-TLSRPT-002",
		Component:      ComponentTLSRPT,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Invalid TLS-RPT record",
		Recommendation: "Publish exactly one record starting with \"v=TLSRPTv1;\" and containing a rua field.",
		References:     []string{RFC8460 + "#section-3"},
	})
	TLSRPTInvalidURI = register(Rule{
		ID:             "MAIL-TLSRPT-003",
		Component:      ComponentTLSRPT,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Invalid TLS-RPT report URI",
		Recommendation: "Use mailto: or https: URIs, separated by commas.",
		References:     []string{RFC8460 + "#section-3"},
	})
	TLSRPTValid = register(Rule{
		ID:        "MAIL-TLSRPT-004",
		Component: ComponentTLSRPT,
		Category:  CategoryInformational,
		Severity:  SeverityPass,
		Title:     "TLS-RPT is configured",
	})
)

// ARC rules.
var (
	ARCPresent = register(Rule{
		ID:         "MAIL-ARC-001",
		Component:  ComponentARC,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "ARC chain present",
		References: []string{RFC8617},
	})
	ARCFail = register(Rule{
		ID:             "MAIL-ARC-002",
		Component:      ComponentARC,
		Category:       CategoryInformational,
		Severity:       SeverityLow,
		Title:          "ARC chain validation failed at an intermediary",
		Recommendation: "An intermediary reported cv=fail. Authentication results carried in the ARC chain cannot be relied upon.",
		References:     []string{RFC8617 + "#section-5.2"},
	})
	ARCInvalid = register(Rule{
		ID:             "MAIL-ARC-003",
		Component:      ComponentARC,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "ARC header set is structurally invalid",
		Recommendation: "Missing, duplicated or misnumbered ARC headers indicate a broken intermediary or tampering.",
		References:     []string{RFC8617 + "#section-4.2"},
	})
)

// Message structure rules.
var (
	MsgMalformedHeaders = register(Rule{
		ID:             "MAIL-MSG-001",
		Component:      ComponentMessage,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Malformed header section",
		Recommendation: "Malformed headers are parsed differently by different software and are used to hide or smuggle header fields. Treat the message with suspicion.",
		References:     []string{RFC5322 + "#section-2.2"},
	})
	MsgMalformedMIME = register(Rule{
		ID:             "MAIL-MSG-002",
		Component:      ComponentMessage,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Malformed MIME structure",
		Recommendation: "Broken MIME structure can make filters and mail clients see different content.",
		References:     []string{RFC2045, RFC2046},
	})
	MsgLineEndings = register(Rule{
		ID:         "MAIL-MSG-003",
		Component:  ComponentMessage,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Non-CRLF line endings",
		References: []string{RFC5322 + "#section-2.1"},
	})
	MsgMissingRequired = register(Rule{
		ID:             "MAIL-MSG-004",
		Component:      ComponentMessage,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Required header missing",
		Recommendation: "RFC 5322 requires exactly one From and one Date header.",
		References:     []string{RFC5322 + "#section-3.6"},
	})
	MsgMissingMessageID = register(Rule{
		ID:             "MAIL-MSG-005",
		Component:      ComponentMessage,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Message-ID missing",
		Recommendation: "Legitimate mail systems add a Message-ID; its absence is common in bulk and malicious mail.",
		References:     []string{RFC5322 + "#section-3.6.4"},
	})
	MsgDuplicateHeader = register(Rule{
		ID:             "MAIL-MSG-006",
		Component:      ComponentMessage,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "Header that must be unique appears more than once",
		Recommendation: "Different software picks different instances of duplicated headers; this is used to show one identity to filters and another to users.",
		References:     []string{RFC5322 + "#section-3.6"},
	})
	MsgReplyToMismatch = register(Rule{
		ID:         "MAIL-MSG-007",
		Component:  ComponentMessage,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Reply-To domain differs from From domain",
		References: []string{RFC5322 + "#section-3.6.2"},
	})
	MsgSenderMismatch = register(Rule{
		ID:         "MAIL-MSG-008",
		Component:  ComponentMessage,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Sender domain differs from From domain",
		References: []string{RFC5322 + "#section-3.6.2"},
	})
	MsgReturnPathMismatch = register(Rule{
		ID:         "MAIL-MSG-009",
		Component:  ComponentMessage,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Return-Path domain differs from From domain",
		References: []string{RFC5321 + "#section-4.4"},
	})
	MsgRiskyAttachment = register(Rule{
		ID:             "MAIL-MSG-010",
		Component:      ComponentMessage,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "Attachment with an executable or container file type",
		Recommendation: "Do not open the attachment outside an isolated analysis environment. MailAuthProbe never extracts or executes attachments.",
	})
	MsgMIMELimit = register(Rule{
		ID:             "MAIL-MSG-011",
		Component:      ComponentMessage,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "MIME structure exceeds analysis limits",
		Recommendation: "Extreme nesting or part counts are used to evade content scanners. Authentication results remain valid.",
	})
	MsgInvalidDate = register(Rule{
		ID:             "MAIL-MSG-012",
		Component:      ComponentMessage,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Invalid Date header",
		Recommendation: "The Date header does not follow RFC 5322 date-time syntax.",
		References:     []string{RFC5322 + "#section-3.3"},
	})
	MsgBadBytes = register(Rule{
		ID:             "MAIL-MSG-013",
		Component:      ComponentMessage,
		Category:       CategoryViolation,
		Severity:       SeverityLow,
		Title:          "Message contains NUL bytes",
		Recommendation: "NUL bytes are not allowed in Internet messages and truncate strings in some software.",
		References:     []string{RFC5322 + "#section-2.1"},
	})
	MsgHeadersOnly = register(Rule{
		ID:         "MAIL-MSG-014",
		Component:  ComponentMessage,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "Message body not available",
		References: []string{RFC6376 + "#section-3.7"},
	})
)

// DKIM message verification rules.
var (
	DKIMSignatureValid = register(Rule{
		ID:         "MAIL-DKIM-020",
		Component:  ComponentDKIM,
		Category:   CategoryInformational,
		Severity:   SeverityPass,
		Title:      "DKIM signature valid",
		References: []string{RFC6376 + "#section-6"},
	})
	DKIMSignatureInvalid = register(Rule{
		ID:             "MAIL-DKIM-021",
		Component:      ComponentDKIM,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "DKIM signature does not verify",
		Recommendation: "Signed header fields were changed after signing, or the signature was forged. Do not trust the signed identity.",
		References:     []string{RFC6376 + "#section-6.1.3"},
	})
	DKIMBodyHashMismatch = register(Rule{
		ID:             "MAIL-DKIM-022",
		Component:      ComponentDKIM,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "DKIM body hash mismatch",
		Recommendation: "The body was modified after signing (by a forwarder, footer injection, or an attacker). Compare with the original message if available.",
		References:     []string{RFC6376 + "#section-6.1.3"},
	})
	DKIMVerifyPermError = register(Rule{
		ID:             "MAIL-DKIM-023",
		Component:      ComponentDKIM,
		Category:       CategoryViolation,
		Severity:       SeverityMedium,
		Title:          "DKIM signature cannot be verified",
		Recommendation: "The signature is malformed or its key is missing, revoked or unsuitable. See the description for the exact reason.",
		References:     []string{RFC6376 + "#section-6.1"},
	})
	DKIMVerifyTempError = register(Rule{
		ID:             "MAIL-DKIM-024",
		Component:      ComponentDKIM,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "DKIM key lookup failed temporarily",
		Recommendation: "Retry the analysis; the result is unknown.",
		References:     []string{RFC6376 + "#section-6.1.2"},
	})
	DKIMUnsigned = register(Rule{
		ID:             "MAIL-DKIM-025",
		Component:      ComponentDKIM,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "Message is not DKIM-signed",
		Recommendation: "Without DKIM, DMARC can only pass through SPF, which breaks on forwarding.",
		References:     []string{RFC6376},
	})
	DKIMInsecureAlgorithm = register(Rule{
		ID:             "MAIL-DKIM-026",
		Component:      ComponentDKIM,
		Category:       CategoryWeakness,
		Severity:       SeverityHigh,
		Title:          "DKIM signature uses rsa-sha1",
		Recommendation: "The signer must switch to rsa-sha256; rsa-sha1 signatures are not accepted.",
		References:     []string{RFC8301 + "#section-3.1"},
	})
	DKIMBodyLength = register(Rule{
		ID:             "MAIL-DKIM-027",
		Component:      ComponentDKIM,
		Category:       CategoryWeakness,
		Severity:       SeverityMedium,
		Title:          "DKIM signature covers only part of the body (l=)",
		Recommendation: "Content after the signed length can be replaced or appended by anyone. Signers should not use l=.",
		References:     []string{RFC6376 + "#section-8.2"},
	})
	DKIMUnsignedHeaders = register(Rule{
		ID:             "MAIL-DKIM-028",
		Component:      ComponentDKIM,
		Category:       CategoryHardening,
		Severity:       SeverityLow,
		Title:          "DKIM signature does not cover important headers",
		Recommendation: "Signers should include Subject, Date, To and Message-ID in h=.",
		References:     []string{RFC6376 + "#section-5.4.1"},
	})
	DKIMExpired = register(Rule{
		ID:             "MAIL-DKIM-029",
		Component:      ComponentDKIM,
		Category:       CategoryInformational,
		Severity:       SeverityMedium,
		Title:          "DKIM signature has expired",
		Recommendation: "The signature's x= time has passed; it no longer authenticates the message.",
		References:     []string{RFC6376 + "#section-3.5"},
	})
	DKIMTooManySignatures = register(Rule{
		ID:             "MAIL-DKIM-030",
		Component:      ComponentDKIM,
		Category:       CategoryInformational,
		Severity:       SeverityLow,
		Title:          "Too many DKIM signatures",
		Recommendation: "Only the first signatures were verified. Large numbers of signatures are used to exhaust verifiers.",
		References:     []string{RFC6376 + "#section-6.1"},
	})
	DKIMHeaderOnlyValid = register(Rule{
		ID:         "MAIL-DKIM-031",
		Component:  ComponentDKIM,
		Category:   CategoryInformational,
		Severity:   SeverityInfo,
		Title:      "DKIM header signature valid; body not checked",
		References: []string{RFC6376 + "#section-6.1.3"},
	})
)
