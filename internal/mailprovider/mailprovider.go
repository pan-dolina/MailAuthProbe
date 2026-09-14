// Package mailprovider recognises hosted mail services from the MX hosts and
// SPF includes of a domain, and records the DKIM selectors that each service
// documents for its customers.
//
// DKIM selectors cannot be enumerated from DNS. Many hosted services,
// however, tell customers to publish keys under fixed selector names, so for
// a domain that uses such a service the keys can be audited without asking
// the user for selectors. Only selectors taken from the providers' own setup
// documentation are listed here; this is not a dictionary for brute-forcing.
package mailprovider

import "strings"

// Provider describes a hosted mail service.
type Provider struct {
	Name string
	// MXSuffixes match MX host names equal to or below one of the suffixes.
	MXSuffixes []string
	// SPFIncludes match include: and redirect= targets exactly.
	SPFIncludes []string
	// DKIMSelectors are the selector names from the provider's documentation,
	// in the order in which they are tried.
	DKIMSelectors []string
	// DKIMNote explains why the selectors cannot be predicted, for providers
	// that generate them per customer.
	DKIMNote string
}

// Known lists the recognised providers. The order is significant: it is the
// order of detected providers and of guessed selectors in reports.
var Known = []Provider{
	{
		// Google Workspace Admin Help, "Set up DKIM": the default selector
		// prefix is "google".
		Name:          "Google Workspace",
		MXSuffixes:    []string{"google.com", "googlemail.com"},
		SPFIncludes:   []string{"_spf.google.com"},
		DKIMSelectors: []string{"google"},
	},
	{
		// Microsoft Learn, "Set up DKIM to sign mail from your Microsoft 365
		// domain": CNAME records for selector1 and selector2.
		Name:          "Microsoft 365",
		MXSuffixes:    []string{"mail.protection.outlook.com", "mx.microsoft"},
		SPFIncludes:   []string{"spf.protection.outlook.com"},
		DKIMSelectors: []string{"selector1", "selector2"},
	},
	{
		// Amazon SES Developer Guide, "Easy DKIM": three CNAME records whose
		// selectors are tokens generated for each identity.
		// SES inbound endpoints are not matched: amazonaws.com also covers
		// arbitrary EC2 hosts.
		Name:        "Amazon SES",
		SPFIncludes: []string{"amazonses.com"},
		DKIMNote:    "Amazon SES (Easy DKIM) generates random selectors for each domain; they are shown in the SES console",
	},
	{
		// Mailchimp, "Set up email domain authentication": k2 and k3 CNAME
		// records; older setups use k1.
		Name:          "Mailchimp",
		SPFIncludes:   []string{"servers.mcsv.net"},
		DKIMSelectors: []string{"k1", "k2", "k3"},
	},
	{
		// Mailchimp Transactional (Mandrill), "Authentication and delivery":
		// selector "mandrill".
		Name:          "Mailchimp Transactional",
		SPFIncludes:   []string{"spf.mandrillapp.com"},
		DKIMSelectors: []string{"mandrill"},
	},
	{
		// Twilio SendGrid, "How to set up domain authentication": CNAME
		// records for s1 and s2.
		Name:          "SendGrid",
		SPFIncludes:   []string{"sendgrid.net"},
		DKIMSelectors: []string{"s1", "s2"},
	},
	{
		// Brevo, "Authenticate your domain": brevo1 and brevo2 CNAME records;
		// domains set up under the Sendinblue name use "mail".
		Name:          "Brevo",
		SPFIncludes:   []string{"spf.brevo.com", "spf.sendinblue.com"},
		DKIMSelectors: []string{"brevo1", "brevo2", "mail"},
	},
	{
		// Mailjet, "How to set up DKIM": selector "mailjet".
		Name:          "Mailjet",
		SPFIncludes:   []string{"spf.mailjet.com"},
		DKIMSelectors: []string{"mailjet"},
	},
	{
		// Postmark, "DKIM": selectors are timestamps followed by "pm".
		Name:        "Postmark",
		SPFIncludes: []string{"spf.mtasv.net"},
		DKIMNote:    "Postmark generates timestamp-based selectors for each domain; they are shown in the Postmark account",
	},
	{
		// Zendesk, "Digitally signing your email with DKIM or DMARC": CNAME
		// records for zendesk1 and zendesk2.
		Name:          "Zendesk",
		SPFIncludes:   []string{"mail.zendesk.com"},
		DKIMSelectors: []string{"zendesk1", "zendesk2"},
	},
	{
		// Fastmail, "Manual DNS configuration": fm1, fm2 and fm3.
		Name:          "Fastmail",
		MXSuffixes:    []string{"messagingengine.com"},
		SPFIncludes:   []string{"spf.messagingengine.com"},
		DKIMSelectors: []string{"fm1", "fm2", "fm3"},
	},
	{
		// Proton Mail, "How to set up DKIM": protonmail, protonmail2 and
		// protonmail3.
		Name:          "Proton Mail",
		MXSuffixes:    []string{"protonmail.ch"},
		SPFIncludes:   []string{"_spf.protonmail.ch"},
		DKIMSelectors: []string{"protonmail", "protonmail2", "protonmail3"},
	},
	{
		// iCloud Mail custom email domains: selector "sig1".
		Name:          "iCloud Mail",
		MXSuffixes:    []string{"mail.icloud.com"},
		SPFIncludes:   []string{"icloud.com"},
		DKIMSelectors: []string{"sig1"},
	},
	{
		// Yandex 360, "Signing emails with DKIM": selector "mail".
		Name:          "Yandex 360",
		MXSuffixes:    []string{"mx.yandex.net"},
		SPFIncludes:   []string{"_spf.yandex.net"},
		DKIMSelectors: []string{"mail"},
	},
}

// Match is a provider detected for a domain.
type Match struct {
	Provider string `json:"provider"`
	// Evidence names the record that identified the provider, such as
	// "MX aspmx.l.google.com" or "SPF include _spf.google.com".
	Evidence      string   `json:"evidence"`
	DKIMSelectors []string `json:"dkim_selectors,omitempty"`
	DKIMNote      string   `json:"dkim_note,omitempty"`
}

// Detect returns the known providers used by a domain with the given MX
// hosts and SPF include/redirect targets, in the order of Known.
func Detect(mxHosts, spfTargets []string) []Match {
	var out []Match
	for _, p := range Known {
		evidence := ""
		for _, h := range mxHosts {
			if matchSuffix(normalize(h), p.MXSuffixes) {
				evidence = "MX " + normalize(h)
				break
			}
		}
		if evidence == "" {
			for _, t := range spfTargets {
				for _, inc := range p.SPFIncludes {
					if normalize(t) == inc {
						evidence = "SPF include " + inc
					}
				}
				if evidence != "" {
					break
				}
			}
		}
		if evidence == "" {
			continue
		}
		out = append(out, Match{
			Provider:      p.Name,
			Evidence:      evidence,
			DKIMSelectors: append([]string(nil), p.DKIMSelectors...),
			DKIMNote:      p.DKIMNote,
		})
	}
	return out
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func matchSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
