package dkim

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver"
	"github.com/pan-dolina/mailauthprobe/internal/findings"
	"github.com/pan-dolina/mailauthprobe/internal/mailprovider"
)

// MaxGuessedSelectors bounds the number of provider default selectors tried
// for one domain.
const MaxGuessedSelectors = 16

// NoKeyRecord is the SelectorAssessment error for a selector without a key
// record.
const NoKeyRecord = "no key record"

// SelectorAssessment is the audit result for one selector.
type SelectorAssessment struct {
	Selector string `json:"selector"`
	Name     string `json:"name"`
	// Provider is set when the selector was not given by the user but taken
	// from the documented defaults of a detected mail provider.
	Provider string     `json:"provider,omitempty"`
	Records  []string   `json:"records,omitempty"`
	Key      *KeyRecord `json:"key,omitempty"`
	Error    string     `json:"error,omitempty"`
}

// Published reports whether a key record exists for the selector.
func (s SelectorAssessment) Published() bool { return len(s.Records) > 0 }

// Assessment is the DKIM part of a domain audit.
type Assessment struct {
	// Providers lists the mail providers detected for the domain.
	Providers []mailprovider.Match `json:"providers,omitempty"`
	Selectors []SelectorAssessment `json:"selectors"`
	Findings  []findings.Finding   `json:"-"`
}

// KeyName returns the DNS name of a DKIM key record.
func KeyName(selector, domain string) string {
	return selector + "._domainkey." + strings.TrimSuffix(domain, ".")
}

// Assess audits the key records of the given selectors.
//
// DKIM selectors cannot be enumerated from DNS. Without selectors, the
// selectors documented by the detected providers are tried instead; a
// missing key under such a guessed selector is not a finding by itself,
// because the domain may use custom selectors.
func Assess(ctx context.Context, r dnsresolver.Resolver, domain string, selectors []string, providers []mailprovider.Match) (*Assessment, error) {
	domain = dnsresolver.Trim(domain)
	a := &Assessment{Providers: providers, Selectors: []SelectorAssessment{}}
	if len(selectors) == 0 {
		return a, a.guess(ctx, r, domain)
	}
	var infraErr error
	seen := map[string]bool{}
	for _, sel := range selectors {
		sel = strings.ToLower(strings.TrimSpace(sel))
		if sel == "" || seen[sel] {
			continue
		}
		seen[sel] = true
		sa, fs, err := assessSelector(ctx, r, domain, sel, "")
		a.Selectors = append(a.Selectors, sa)
		a.Findings = append(a.Findings, fs...)
		if err != nil {
			infraErr = err
		}
	}
	return a, infraErr
}

const selectorAdvice = "Pass --dkim-selector to audit specific keys, or analyse a signed message to discover the selectors in use."

// guess tries the default selectors of the detected providers.
func (a *Assessment) guess(ctx context.Context, r dnsresolver.Resolver, domain string) error {
	var infraErr error
	seen := map[string]bool{}
	tried := 0
	for _, p := range a.Providers {
		for _, sel := range p.DKIMSelectors {
			if seen[sel] || tried == MaxGuessedSelectors {
				continue
			}
			seen[sel] = true
			tried++
			sa, fs, err := assessSelector(ctx, r, domain, sel, p.Provider)
			a.Selectors = append(a.Selectors, sa)
			a.Findings = append(a.Findings, fs...)
			if err != nil {
				infraErr = err
			}
		}
	}

	var found, missing, notes []string
	for _, p := range a.Providers {
		if p.DKIMNote != "" {
			notes = append(notes, p.DKIMNote+".")
		}
		var published, absent []string
		failed := false
		for _, sa := range a.Selectors {
			switch {
			case sa.Provider != p.Provider:
			case sa.Published():
				published = append(published, sa.Selector)
			case sa.Error == NoKeyRecord:
				absent = append(absent, sa.Selector)
			default:
				failed = true
			}
		}
		switch {
		case len(published) > 0:
			found = append(found, fmt.Sprintf("%s (%s)", p.Provider, strings.Join(published, ", ")))
		case len(absent) > 0 && !failed:
			missing = append(missing, fmt.Sprintf("%s (%s)", p.Provider, strings.Join(absent, ", ")))
		}
	}

	var desc []string
	if len(missing) > 0 {
		desc = append(desc, fmt.Sprintf("No DKIM key was found under the documented default selectors of %s; the domain may use custom selectors, or DKIM signing may not be enabled for it there.", strings.Join(missing, ", ")))
	}
	desc = append(desc, notes...)
	if len(found) > 0 {
		desc = append([]string{fmt.Sprintf("DKIM keys were found under the documented default selectors of %s. Other selectors cannot be enumerated from DNS and were not audited.", strings.Join(found, ", "))}, desc...)
		a.Findings = append(a.Findings, findings.DKIMSelectorsGuessed.New(domain, strings.Join(desc, " ")))
		return infraErr
	}
	desc = append([]string{"DKIM keys are published under selector names that cannot be enumerated from DNS."}, desc...)
	desc = append(desc, selectorAdvice)
	a.Findings = append(a.Findings, findings.DKIMNoSelector.New(domain, strings.Join(desc, " ")))
	return infraErr
}

func assessSelector(ctx context.Context, r dnsresolver.Resolver, domain, sel, provider string) (SelectorAssessment, []findings.Finding, error) {
	name := KeyName(sel, domain)
	sa := SelectorAssessment{Selector: sel, Name: name, Provider: provider}
	var fs []findings.Finding
	add := func(f findings.Finding) { fs = append(fs, f) }

	if !dnsresolver.ValidDomain(name) {
		sa.Error = "invalid selector"
		if provider == "" {
			add(findings.DKIMKeyNotFound.New(name, fmt.Sprintf("%q is not a valid DKIM selector name.", sel)))
		}
		return sa, fs, nil
	}
	txts, err := r.LookupTXT(ctx, name)
	switch {
	case dnsresolver.IsNXDomain(err) || (err == nil && len(txts) == 0):
		sa.Error = NoKeyRecord
		if provider == "" {
			add(findings.DKIMKeyNotFound.New(name, fmt.Sprintf("No DKIM key record exists at %s. Messages signed with selector %q cannot be verified.", name, sel)))
		}
		return sa, fs, nil
	case err != nil:
		sa.Error = err.Error()
		add(findings.DNSLookupFailed.New(name, "The DKIM key lookup failed.", err.Error()))
		if dnsresolver.IsInfrastructure(err) {
			return sa, fs, err
		}
		return sa, fs, nil
	}
	sa.Records = txts
	if len(txts) > 1 {
		add(findings.DKIMMultipleKeys.New(name, fmt.Sprintf("%s has %d TXT records; verifiers pick one arbitrarily, so signatures may fail intermittently.", name, len(txts)), txts...))
	}

	key, err := ParseKeyRecord(txts[0])
	if err != nil {
		sa.Error = err.Error()
		add(findings.DKIMInvalidKey.New(name, fmt.Sprintf("The DKIM key record at %s is invalid: %v.", name, err), txts[0]))
		return sa, fs, nil
	}
	sa.Key = key
	fs = append(fs, KeyFindings(name, key)...)
	if findings.Max(fs) <= findings.SeverityInfo && !key.Revoked {
		add(findings.DKIMKeyValid.New(name, fmt.Sprintf("Valid %s key (%d bits) for selector %q.", strings.ToUpper(key.KeyType), key.KeyBits, sel), txts[0]))
	}
	return sa, fs, nil
}

// KeyFindings evaluates the security properties of a parsed key record.
func KeyFindings(name string, key *KeyRecord) []findings.Finding {
	var fs []findings.Finding
	add := func(f findings.Finding) { fs = append(fs, f) }
	if key.Revoked {
		add(findings.DKIMKeyRevoked.New(name, fmt.Sprintf("The key at %s has an empty p= tag, which means it has been revoked. Signatures using it fail.", name), key.Raw))
		return fs
	}
	if !key.AllowsEmail() {
		add(findings.DKIMKeyServiceMismatch.New(name, fmt.Sprintf("The key at %s is restricted to service types %v and cannot be used for e-mail.", name, key.Services), key.Raw))
	}
	if len(key.HashAlgs) > 0 && !slices.Contains(key.HashAlgs, "sha256") {
		add(findings.DKIMKeySHA1Only.New(name, fmt.Sprintf("The key at %s permits only %v; RFC 8301 forbids rsa-sha1, so no valid signature can use this key.", name, key.HashAlgs), key.Raw))
	}
	if key.KeyType == KeyTypeRSA {
		switch {
		case key.KeyBits < 1024:
			add(findings.DKIMKeyTooShort.New(name, fmt.Sprintf("The RSA key at %s is %d bits. Verifiers must not accept keys shorter than 1024 bits and such keys can be factored.", name, key.KeyBits)))
		case key.KeyBits < 2048:
			add(findings.DKIMKeyWeak.New(name, fmt.Sprintf("The RSA key at %s is %d bits.", name, key.KeyBits)))
		case key.KeyBits > 4096:
			add(findings.DKIMKeyTooLong.New(name, fmt.Sprintf("The RSA key at %s is %d bits; verifiers are only required to support keys up to 4096 bits.", name, key.KeyBits)))
		}
		if key.PKCS1 {
			add(findings.DKIMKeyPKCS1.New(name, fmt.Sprintf("The key at %s is encoded as a bare RSAPublicKey rather than SubjectPublicKeyInfo; some verifiers reject it.", name), key.Raw))
		}
	}
	if key.KeyType == KeyTypeEd25519 {
		add(findings.DKIMKeyEd25519.New(name, fmt.Sprintf("The key at %s is Ed25519 (RFC 8463). Many verifiers do not support Ed25519 yet; sign with an RSA key as well.", name)))
	}
	if key.Testing() {
		add(findings.DKIMKeyTesting.New(name, fmt.Sprintf("The key at %s has t=y (testing mode); verifiers may treat failures as if the message were unsigned.", name), key.Raw))
	}
	for _, t := range key.UnknownTags {
		add(findings.DKIMKeyUnknownTag.New(name, fmt.Sprintf("The key record at %s contains the unknown tag %q, which verifiers ignore.", name, t)))
	}
	return fs
}
