package dmarc

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// OrganizationalDomain returns the organizational domain of d using the
// Public Suffix List (RFC 7489 section 3.2): the public suffix plus one label.
// If d is itself a public suffix, d is returned.
func OrganizationalDomain(d string) string {
	d = normalize(d)
	if d == "" {
		return ""
	}
	org, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return org
}

// Aligned reports whether an authenticated identifier domain is aligned with
// the RFC5322.From domain under the given mode (RFC 7489 section 3.1).
func Aligned(authDomain, fromDomain string, mode Mode) bool {
	a, f := normalize(authDomain), normalize(fromDomain)
	if a == "" || f == "" {
		return false
	}
	if a == f {
		return true
	}
	if mode == ModeStrict {
		return false
	}
	return OrganizationalDomain(a) == OrganizationalDomain(f)
}

func normalize(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}
