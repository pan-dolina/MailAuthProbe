package dmarc

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestIsDMARC(t *testing.T) {
	tests := []struct {
		txt  string
		want bool
	}{
		{"v=DMARC1; p=none", true},
		{"v=DMARC1", true},
		{"v = DMARC1 ; p=reject", true},
		{"v=dmarc1; p=none", false},
		{"p=none; v=DMARC1", false},
		{"v=DMARC10; p=none", false},
		{"v=spf1 -all", false},
	}
	for _, tt := range tests {
		if got := IsDMARC(tt.txt); got != tt.want {
			t.Errorf("IsDMARC(%q) = %v", tt.txt, got)
		}
	}
}

func TestParseDefaultsAndValues(t *testing.T) {
	rec, err := Parse("v=DMARC1; p=reject")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Policy != PolicyReject || rec.SubdomainPolicy != "" || rec.EffectiveSubdomainPolicy() != PolicyReject ||
		rec.Percent != 100 || rec.ADKIM != ModeRelaxed || rec.ASPF != ModeRelaxed ||
		!slices.Equal(rec.FO, []string{"0"}) || rec.RF != "afrf" || rec.RI != 86400 || len(rec.Issues) != 0 {
		t.Errorf("defaults = %+v", rec)
	}

	rec, err = Parse("v=DMARC1 ;P=Quarantine; sp=none; pct=25; adkim=S; aspf=s; " +
		"rua=mailto:agg@example.com!10m,mailto:dmarc@reports.example.net; ruf=mailto:forensic@example.com; " +
		"fo=1:d:s; rf=afrf; ri=3600;")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Policy != PolicyQuarantine || rec.SubdomainPolicy != PolicyNone || rec.Percent != 25 ||
		rec.ADKIM != ModeStrict || rec.ASPF != ModeStrict || rec.RI != 3600 ||
		!slices.Equal(rec.FO, []string{"1", "d", "s"}) || len(rec.Issues) != 0 {
		t.Errorf("parsed = %+v, issues %+v", rec, rec.Issues)
	}
	if len(rec.RUA) != 2 || rec.RUA[0].Address != "agg@example.com" || rec.RUA[0].MaxSize != "10m" ||
		rec.RUA[1].Domain != "reports.example.net" || len(rec.RUF) != 1 {
		t.Errorf("rua = %+v, ruf = %+v", rec.RUA, rec.RUF)
	}
	if !rec.HasTag("fo") || rec.HasTag("np") {
		t.Error("HasTag")
	}
}

func TestParseFatalErrors(t *testing.T) {
	tests := []struct{ txt, msg string }{
		{"p=reject; v=DMARC1", `start with "v=DMARC1"`},
		{"v=DMARC1; sp=reject", "required tag p is missing"},
		{"v=DMARC1; p=block", "invalid p tag"},
		{"v=DMARC1; p=reject; garbage", "malformed tag"},
		{"v=DMARC1; p=reject; sp=rejct", "invalid sp tag"},
		{"v=DMARC1; =x; p=none", "malformed tag"},
	}
	for _, tt := range tests {
		_, err := Parse(tt.txt)
		var pe *ParseError
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), tt.msg) {
			t.Errorf("Parse(%q) err = %v, want %q", tt.txt, err, tt.msg)
		}
	}
}

func TestParseImpliedPolicy(t *testing.T) {
	for _, txt := range []string{
		"v=DMARC1; rua=mailto:d@example.com",
		"v=DMARC1; p=bogus; sp=reject; rua=mailto:d@example.com",
		"v=DMARC1; p=reject; sp=rejct; rua=mailto:d@example.com",
	} {
		rec, err := Parse(txt)
		if err != nil || rec.Policy != PolicyNone || !rec.PolicyImplied || rec.EffectiveSubdomainPolicy() != PolicyNone {
			t.Errorf("Parse(%q) = %+v, %v", txt, rec, err)
		}
	}
}

func TestParseIssues(t *testing.T) {
	tests := []struct {
		txt  string
		kind IssueKind
		tag  string
	}{
		{"v=DMARC1; p=none; p=reject", IssueDuplicateTag, "p"},
		{"v=DMARC1; p=none; v=DMARC1", IssueDuplicateTag, "v"},
		{"v=DMARC1; p=none; sp=block; rua=mailto:d@example.com", IssueInvalidValue, "sp"},
		{"v=DMARC1; p=none; pct=101", IssueInvalidValue, "pct"},
		{"v=DMARC1; p=none; pct=-1", IssueInvalidValue, "pct"},
		{"v=DMARC1; p=none; pct=50%", IssueInvalidValue, "pct"},
		{"v=DMARC1; p=none; adkim=relaxed", IssueInvalidValue, "adkim"},
		{"v=DMARC1; p=none; aspf=x", IssueInvalidValue, "aspf"},
		{"v=DMARC1; p=none; fo=2", IssueInvalidValue, "fo"},
		{"v=DMARC1; p=none; fo=", IssueInvalidValue, "fo"},
		{"v=DMARC1; p=none; rf=iodef", IssueInvalidValue, "rf"},
		{"v=DMARC1; p=none; ri=daily", IssueInvalidValue, "ri"},
		{"v=DMARC1; p=none; np=block", IssueInvalidValue, "np"},
		{"v=DMARC1; p=none; rua=dmarc@example.com", IssueInvalidURI, "rua"},
		{"v=DMARC1; p=none; rua=mailto:dmarc", IssueInvalidURI, "rua"},
		{"v=DMARC1; p=none; rua=mailto:d@localhost", IssueInvalidURI, "rua"},
		{"v=DMARC1; p=none; rua=mailto:d@example.com!10x", IssueInvalidURI, "rua"},
		{"v=DMARC1; p=none; ruf=ftp://example.com/r", IssueInvalidURI, "ruf"},
		{"v=DMARC1; p=none; rua=https://", IssueInvalidURI, "rua"},
		{"v=DMARC1; p=none; rua=mailto:a@example.com,", IssueInvalidURI, "rua"},
		{"v=DMARC1; p=none; foo=bar", IssueUnknownTag, "foo"},
	}
	for _, tt := range tests {
		t.Run(tt.txt, func(t *testing.T) {
			rec, err := Parse(tt.txt)
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.Issues) != 1 || rec.Issues[0].Kind != tt.kind || rec.Issues[0].Tag != tt.tag {
				t.Errorf("issues = %+v", rec.Issues)
			}
		})
	}
}

func TestParseDuplicateKeepsFirst(t *testing.T) {
	rec, err := Parse("v=DMARC1; p=reject; p=none")
	if err != nil || rec.Policy != PolicyReject {
		t.Errorf("policy = %v, %v", rec.Policy, err)
	}
}

func TestParseKnownBisTags(t *testing.T) {
	rec, err := Parse("v=DMARC1; p=reject; np=reject; psd=n; t=n")
	if err != nil || len(rec.Issues) != 0 {
		t.Errorf("issues = %+v, %v", rec.Issues, err)
	}
}
