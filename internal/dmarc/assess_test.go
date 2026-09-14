package dmarc

import (
	"context"
	"slices"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/pan-dolina/mailauthprobe/internal/findings"
)

func ids(fs []findings.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	slices.Sort(out)
	return out
}

func TestDiscover(t *testing.T) {
	zone := dnstest.MustParseZone(`
_dmarc.example.com.      TXT "v=DMARC1; p=reject; sp=quarantine"
_dmarc.example.com.      TXT "unrelated"
_dmarc.own.example.com.  TXT "v=DMARC1; p=none"
_dmarc.multi.test.       TXT "v=DMARC1; p=none"
_dmarc.multi.test.       TXT "v=DMARC1; p=reject"
_dmarc.flaky.test.       SERVFAIL
`)
	ctx := context.Background()
	tests := []struct {
		domain, policyDomain string
		inherited            bool
		policy               Policy
		wantErr              bool
	}{
		{"example.com", "example.com", false, PolicyReject, false},
		{"mail.eu.example.com", "example.com", true, PolicyReject, false},
		{"own.example.com", "own.example.com", false, PolicyNone, false},
		{"nothing.example.org", "", false, "", false},
		{"multi.test", "multi.test", false, "", false},
		{"sub.flaky.test", "", false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			d, err := Discover(ctx, zone, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if d.PolicyDomain != tt.policyDomain || d.Inherited != tt.inherited {
				t.Errorf("policy domain = %q inherited = %v", d.PolicyDomain, d.Inherited)
			}
			var got Policy
			if p := d.Policy(); p != nil {
				got = p.Policy
			}
			if got != tt.policy {
				t.Errorf("policy = %q, want %q", got, tt.policy)
			}
		})
	}
}

func TestAssess(t *testing.T) {
	tests := []struct {
		name    string
		zone    string
		domain  string
		want    []string
		wantErr bool
	}{
		{"reject", `_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"`, "example.com",
			[]string{"MAIL-DMARC-017"}, false},
		{"missing", `example.com. TXT "v=spf1 -all"`, "example.com", []string{"MAIL-DMARC-001"}, false},
		{"multiple", "_dmarc.example.com. TXT \"v=DMARC1; p=none\"\n_dmarc.example.com. TXT \"v=DMARC1; p=reject\"", "example.com",
			[]string{"MAIL-DMARC-002"}, false},
		{"invalid", `_dmarc.example.com. TXT "v=DMARC1; p=maybe"`, "example.com", []string{"MAIL-DMARC-003"}, false},
		{"implied none", `_dmarc.example.com. TXT "v=DMARC1; rua=mailto:d@example.com"`, "example.com",
			[]string{"MAIL-DMARC-003", "MAIL-DMARC-004"}, false},
		{"none without rua", `_dmarc.example.com. TXT "v=DMARC1; p=none"`, "example.com",
			[]string{"MAIL-DMARC-004", "MAIL-DMARC-008"}, false},
		{"quarantine partial", `_dmarc.example.com. TXT "v=DMARC1; p=quarantine; pct=50; rua=mailto:d@example.com"`, "example.com",
			[]string{"MAIL-DMARC-005", "MAIL-DMARC-006"}, false},
		{"weak subdomain policy", `_dmarc.example.com. TXT "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"`, "example.com",
			[]string{"MAIL-DMARC-007"}, false},
		{"ruf and strict", `_dmarc.example.com. TXT "v=DMARC1; p=reject; adkim=s; rua=mailto:d@example.com; ruf=mailto:f@example.com"`, "example.com",
			[]string{"MAIL-DMARC-009", "MAIL-DMARC-016", "MAIL-DMARC-017"}, false},
		{"tag issues", `_dmarc.example.com. TXT "v=DMARC1; p=reject; p=none; pct=abc; foo=bar; rua=bogus, mailto:d@example.com; fo=1"`, "example.com",
			[]string{"MAIL-DMARC-010", "MAIL-DMARC-011", "MAIL-DMARC-012", "MAIL-DMARC-013", "MAIL-DMARC-018"}, false},
		{"inherited from org domain", `_dmarc.example.com. TXT "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"`, "news.example.com",
			[]string{"MAIL-DMARC-005", "MAIL-DMARC-015"}, false},
		{"external destination unauthorized", `_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:d@reports.example.net"`, "example.com",
			[]string{"MAIL-DMARC-014"}, false},
		{"external destination authorized", `
_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:d@reports.example.net,mailto:x@sub.example.com"
example.com._report._dmarc.reports.example.net. TXT "v=DMARC1"
`, "example.com", []string{"MAIL-DMARC-017"}, false},
		{"external https destination unauthorized", `_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=https://reports.example.net/dmarc"`, "example.com",
			[]string{"MAIL-DMARC-014"}, false},
		{"authorization must be a DMARC record", `
_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:d@reports.example.net"
example.com._report._dmarc.reports.example.net. TXT "v=DMARC1x"
`, "example.com", []string{"MAIL-DMARC-014"}, false},
		{"lookup failure", `_dmarc.example.com. TIMEOUT`, "example.com", []string{"MAIL-DNS-001"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Assess(context.Background(), dnstest.MustParseZone(tt.zone), tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if got := ids(a.Findings); !slices.Equal(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
				for _, f := range a.Findings {
					t.Logf("  %s [%s] %s", f.ID, f.Severity, f.Description)
				}
			}
		})
	}
}

func TestAssessPctZeroIsHigh(t *testing.T) {
	a, _ := Assess(context.Background(), dnstest.MustParseZone(`_dmarc.example.com. TXT "v=DMARC1; p=reject; pct=0; rua=mailto:d@example.com"`), "example.com")
	for _, f := range a.Findings {
		if f.ID == "MAIL-DMARC-006" && f.Severity != findings.SeverityHigh {
			t.Errorf("pct=0 severity = %v", f.Severity)
		}
	}
}
