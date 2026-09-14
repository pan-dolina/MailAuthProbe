package dmarc

import (
	"context"
	"slices"
	"testing"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
)

func TestEvaluateMessage(t *testing.T) {
	zone := dnstest.MustParseZone(`
_dmarc.example.com.     TXT "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"
_dmarc.none.example.    TXT "v=DMARC1; p=none"
_dmarc.strict.example.  TXT "v=DMARC1; p=reject; adkim=s; aspf=s"
_dmarc.pct.example.     TXT "v=DMARC1; p=quarantine; pct=20"
_dmarc.bad.example.     TXT "v=DMARC1; p=maybe"
_dmarc.flaky.example.   SERVFAIL
`)
	tests := []struct {
		name        string
		in          MessageInput
		result      string
		disposition Policy
		ids         []string
	}{
		{"aligned DKIM", MessageInput{FromHeaders: []string{"a@example.com"}, DKIM: []DKIMInput{{"example.com", "pass"}}},
			MessagePass, "", []string{"MAIL-DMARC-030"}},
		{"relaxed DKIM subdomain", MessageInput{FromHeaders: []string{"a@example.com"}, DKIM: []DKIMInput{{"mail.example.com", "pass"}}},
			MessagePass, "", []string{"MAIL-DMARC-030"}},
		{"relaxed SPF subdomain", MessageInput{FromHeaders: []string{"a@news.example.com"}, SPFResult: "pass", SPFDomain: "bounce.example.com"},
			MessagePass, "", []string{"MAIL-DMARC-030"}},
		{"reject: unaligned third party", MessageInput{FromHeaders: []string{"Alice <a@example.com>"}, SPFResult: "pass", SPFDomain: "esp.example",
			DKIM: []DKIMInput{{"esp.example", "pass"}, {"example.com", "fail"}}},
			MessageFail, PolicyReject, []string{"MAIL-DMARC-031", "MAIL-DMARC-036", "MAIL-DMARC-037"}},
		{"subdomain policy for inherited", MessageInput{FromHeaders: []string{"a@shop.example.com"}, SPFResult: "fail", SPFDomain: "shop.example.com"},
			MessageFail, PolicyQuarantine, []string{"MAIL-DMARC-031"}},
		{"none policy fails as medium", MessageInput{FromHeaders: []string{"a@none.example"}, SPFResult: "softfail", SPFDomain: "none.example"},
			MessageFail, PolicyNone, []string{"MAIL-DMARC-031"}},
		{"strict alignment fail", MessageInput{FromHeaders: []string{"a@strict.example"}, SPFResult: "pass", SPFDomain: "bounces.strict.example",
			DKIM: []DKIMInput{{"mail.strict.example", "pass"}}},
			MessageFail, PolicyReject, []string{"MAIL-DMARC-031", "MAIL-DMARC-035", "MAIL-DMARC-035"}},
		{"strict alignment exact pass", MessageInput{FromHeaders: []string{"a@strict.example"}, DKIM: []DKIMInput{{"STRICT.example", "pass"}}},
			MessagePass, "", []string{"MAIL-DMARC-030"}},
		{"pct", MessageInput{FromHeaders: []string{"a@pct.example"}, SPFResult: "none", SPFDomain: "pct.example"}, MessageFail, PolicyQuarantine, []string{"MAIL-DMARC-031"}},
		{"spf not evaluated is indeterminate", MessageInput{FromHeaders: []string{"a@example.com"}}, MessageIndeterminate, "", []string{"MAIL-DMARC-038"}},
		{"header-only dkim is indeterminate", MessageInput{FromHeaders: []string{"a@example.com"}, SPFResult: "fail", SPFDomain: "example.com", DKIM: []DKIMInput{{"example.com", "neutral"}}}, MessageIndeterminate, "", []string{"MAIL-DMARC-038"}},
		{"spf temperror", MessageInput{FromHeaders: []string{"a@example.com"}, SPFResult: "temperror", SPFDomain: "example.com"}, MessageTempError, "", []string{"MAIL-DMARC-034"}},
		{"dkim temperror", MessageInput{FromHeaders: []string{"a@example.com"}, SPFResult: "fail", SPFDomain: "example.com", DKIM: []DKIMInput{{"example.com", "temperror"}}}, MessageTempError, "", []string{"MAIL-DMARC-034"}},
		{"no policy", MessageInput{FromHeaders: []string{"a@unprotected.example"}}, MessageNone, "", []string{"MAIL-DMARC-032"}},
		{"invalid policy", MessageInput{FromHeaders: []string{"a@bad.example"}}, MessageNone, "", []string{"MAIL-DMARC-032"}},
		{"temperror", MessageInput{FromHeaders: []string{"a@flaky.example"}}, MessageTempError, "", []string{"MAIL-DMARC-034"}},
		{"no From", MessageInput{}, MessagePermError, "", []string{"MAIL-DMARC-033"}},
		{"two From headers", MessageInput{FromHeaders: []string{"a@example.com", "b@evil.example"}}, MessagePermError, "", []string{"MAIL-DMARC-033"}},
		{"two mailboxes", MessageInput{FromHeaders: []string{"a@example.com, b@evil.example"}}, MessagePermError, "", []string{"MAIL-DMARC-033"}},
		{"unparseable From", MessageInput{FromHeaders: []string{"not an address"}}, MessagePermError, "", []string{"MAIL-DMARC-033"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := EvaluateMessage(context.Background(), zone, tt.in)
			if ev.Result != tt.result || ev.Disposition != tt.disposition {
				t.Errorf("result = %s disposition = %q (%s), want %s %q", ev.Result, ev.Disposition, ev.Reason, tt.result, tt.disposition)
			}
			if got := ids(ev.Findings); !slices.Equal(got, tt.ids) {
				t.Errorf("findings = %v, want %v", got, tt.ids)
				for _, f := range ev.Findings {
					t.Logf("  %s [%s] %s", f.ID, f.Severity, f.Description)
				}
			}
		})
	}
}

func TestEvaluateMessageSeverity(t *testing.T) {
	zone := dnstest.MustParseZone(`_dmarc.none.example. TXT "v=DMARC1; p=none"`)
	ev := EvaluateMessage(context.Background(), zone, MessageInput{FromHeaders: []string{"a@none.example"}, SPFResult: "fail", SPFDomain: "none.example"})
	if ev.Findings[0].Severity.String() != "medium" {
		t.Errorf("p=none failure severity = %v", ev.Findings[0].Severity)
	}
}
