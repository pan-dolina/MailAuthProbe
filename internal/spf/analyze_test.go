package spf

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

func analyze(t *testing.T, zone string, domain string) (*Analysis, error) {
	t.Helper()
	a := &Analyzer{Resolver: dnstest.MustParseZone(zone)}
	return a.Analyze(context.Background(), domain)
}

func findingIDs(fs []findings.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestAnalyzeFindings(t *testing.T) {
	tests := []struct {
		name    string
		zone    string
		want    []string
		wantErr bool
	}{
		{
			name: "valid record",
			zone: `
example.test. TXT "v=spf1 ip4:192.0.2.0/24 include:_spf.example.test -all"
_spf.example.test. TXT "v=spf1 ip6:2001:db8::/48 -all"
`,
			want: []string{"MAIL-SPF-022"},
		},
		{"missing", `example.test. TXT "hello"`, []string{"MAIL-SPF-001"}, false},
		{"nxdomain", `other.test. TXT "v=spf1 -all"`, []string{"MAIL-SPF-001"}, false},
		{"multiple", "example.test. TXT \"v=spf1 -all\"\nexample.test. TXT \"v=spf1 ~all\"", []string{"MAIL-SPF-002"}, false},
		{"syntax", `example.test. TXT "v=spf1 ip4:192.0.2.300 -all"`, []string{"MAIL-SPF-003"}, false},
		{"plus all", `example.test. TXT "v=spf1 +all"`, []string{"MAIL-SPF-007"}, false},
		{"implicit plus all", `example.test. TXT "v=spf1 all"`, []string{"MAIL-SPF-007"}, false},
		{"neutral all", `example.test. TXT "v=spf1 ip4:192.0.2.1 ?all"`, []string{"MAIL-SPF-008"}, false},
		{"softfail all", `example.test. TXT "v=spf1 ip4:192.0.2.1 ~all"`, []string{"MAIL-SPF-009", "MAIL-SPF-022"}, false},
		{"no all", `example.test. TXT "v=spf1 ip4:192.0.2.1"`, []string{"MAIL-SPF-010"}, false},
		{"broad ipv4", `example.test. TXT "v=spf1 ip4:10.0.0.0/8 -all"`, []string{"MAIL-SPF-011"}, false},
		{"broad ipv6", `example.test. TXT "v=spf1 ip6:2001:db8::/16 -all"`, []string{"MAIL-SPF-011"}, false},
		{"negative broad range is fine", `example.test. TXT "v=spf1 -ip4:10.0.0.0/8 ip4:192.0.2.1 -all"`, []string{"MAIL-SPF-022"}, false},
		{"ptr", "example.test. TXT \"v=spf1 ptr -all\"", []string{"MAIL-SPF-012", "MAIL-SPF-022"}, false},
		{"include without record", `example.test. TXT "v=spf1 include:none.test -all"`, []string{"MAIL-SPF-013"}, false},
		{"redirect without record", "example.test. TXT \"v=spf1 redirect=none.test\"\nnone.test. TXT \"x\"", []string{"MAIL-SPF-013"}, false},
		{"include with plus all", "example.test. TXT \"v=spf1 include:bad.test -all\"\nbad.test. TXT \"v=spf1 +all\"", []string{"MAIL-SPF-007"}, false},
		{"include temperror", "example.test. TXT \"v=spf1 include:flaky.test -all\"\nflaky.test. SERVFAIL", []string{"MAIL-SPF-014"}, true},
		{"terms after all", `example.test. TXT "v=spf1 -all ip4:192.0.2.1"`, []string{"MAIL-SPF-015", "MAIL-SPF-022"}, false},
		{"redirect ignored", "example.test. TXT \"v=spf1 -all redirect=other.test\"\nother.test. TXT \"v=spf1 -all\"", []string{"MAIL-SPF-016", "MAIL-SPF-022"}, false},
		{"p macro", "example.test. TXT \"v=spf1 exists:%{p}.allow.test -all\"", []string{"MAIL-SPF-018", "MAIL-SPF-023", "MAIL-SPF-022"}, false},
		{"exp and unknown modifier", `example.test. TXT "v=spf1 -all exp=why.example.test x-custom=1"`, []string{"MAIL-SPF-019", "MAIL-SPF-020", "MAIL-SPF-022"}, false},
		{"dynamic include", `example.test. TXT "v=spf1 include:%{ir}.%{v}.rbl.test -all"`, []string{"MAIL-SPF-022", "MAIL-SPF-023"}, false},
		{"void a target", `example.test. TXT "v=spf1 a:gone.example.test -all"`, []string{"MAIL-SPF-022", "MAIL-SPF-025"}, false},
		{"record too long", `example.test. TXT "v=spf1 ` + strings.Repeat("ip4:192.0.2.1 ", 35) + `-all"`, []string{"MAIL-SPF-022", "MAIL-SPF-024"}, false},
		{"root lookup fails", `example.test. TIMEOUT`, []string{"MAIL-DNS-001"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := analyze(t, tt.zone, "example.test")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if got := findingIDs(res.Findings); !slices.Equal(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
				for _, f := range res.Findings {
					t.Logf("  %s [%s] %s", f.ID, f.Severity, f.Description)
				}
			}
		})
	}
}

func TestAnalyzeSeverityContext(t *testing.T) {
	res, _ := analyze(t, `
example.test. TXT "v=spf1 include:inc.test -all"
inc.test.     TXT "v=spf1 ip4:192.0.2.1"
`, "example.test")
	for _, f := range res.Findings {
		if f.ID == findings.SPFNoAll.ID && f.Severity != findings.SeverityInfo {
			t.Errorf("missing all inside include should be info, got %v", f.Severity)
		}
	}

	res, _ = analyze(t, `example.test. TXT "v=spf1 ip4:0.0.0.0/0 -all"`, "example.test")
	if len(res.Findings) == 0 || res.Findings[0].Severity != findings.SeverityCritical {
		t.Errorf("ip4:0.0.0.0/0 should be critical: %+v", res.Findings)
	}
}

func TestAnalyzeLookupCounting(t *testing.T) {
	zone := `
example.test.    TXT "v=spf1 a mx include:a.inc.test include:b.inc.test exists:%{i}.x.test ptr:example.test redirect=r.test"
example.test.    A   192.0.2.1
example.test.    MX  10 example.test.
a.inc.test.      TXT "v=spf1 include:c.inc.test ip4:192.0.2.2 -all"
b.inc.test.      TXT "v=spf1 mx:example.test -all"
c.inc.test.      TXT "v=spf1 a:example.test -all"
r.test.          TXT "v=spf1 -all"
`
	res, err := analyze(t, zone, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	// Root: a, mx, include, include, exists, ptr, redirect = 7
	// a.inc.test: include = 1, c.inc.test: a = 1, b.inc.test: mx = 1
	if res.Tree.Lookups != 7 || res.TotalLookups != 10 {
		t.Errorf("root lookups = %d, total = %d; want 7 and 10\n%s", res.Tree.Lookups, res.TotalLookups, strings.Join(lookupBreakdown(res.Tree), "\n"))
	}
	if len(res.Tree.Children) != 3 || res.Tree.Children[2].Via != "redirect=r.test" {
		t.Errorf("children = %+v", res.Tree.Children)
	}
	if got := res.Tree.Children[0].Children[0].Domain; got != "c.inc.test" {
		t.Errorf("grandchild = %s", got)
	}
	if !slices.Contains(findingIDs(res.Findings), "MAIL-SPF-017") {
		t.Errorf("expected near-limit finding, got %v", findingIDs(res.Findings))
	}
}

func TestAnalyzeLookupLimitExceeded(t *testing.T) {
	var b strings.Builder
	var terms []string
	for i := range 4 {
		fmt.Fprintf(&b, "p%d.test. TXT \"v=spf1 include:q%d.test include:q%d.test -all\"\n", i, i, i+10)
		fmt.Fprintf(&b, "q%d.test. TXT \"v=spf1 ip4:192.0.2.%d -all\"\n", i, i)
		fmt.Fprintf(&b, "q%d.test. TXT \"v=spf1 ip4:192.0.2.%d -all\"\n", i+10, i+10)
		terms = append(terms, fmt.Sprintf("include:p%d.test", i))
	}
	fmt.Fprintf(&b, "example.test. TXT \"v=spf1 %s -all\"\n", strings.Join(terms, " "))
	res, err := analyze(t, b.String(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalLookups != 12 {
		t.Errorf("total = %d, want 12", res.TotalLookups)
	}
	ids := findingIDs(res.Findings)
	if !slices.Contains(ids, "MAIL-SPF-005") || slices.Contains(ids, "MAIL-SPF-022") {
		t.Errorf("findings = %v", ids)
	}
}

func TestAnalyzeLoops(t *testing.T) {
	res, err := analyze(t, `
example.test. TXT "v=spf1 include:b.test -all"
b.test.       TXT "v=spf1 redirect=example.test"
`, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	loop := res.Tree.Children[0].Children[0]
	if !loop.Loop {
		t.Fatalf("loop node not marked: %+v", res.Tree)
	}
	var f *findings.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "MAIL-SPF-004" {
			f = &res.Findings[i]
		}
	}
	if f == nil || f.Evidence[0] != "example.test -> b.test -> example.test" {
		t.Errorf("loop finding = %+v", f)
	}
}

func TestAnalyzeBoundsHostileTrees(t *testing.T) {
	// A wide tree: every record includes ten others. Without a node bound
	// this would issue thousands of queries.
	var b strings.Builder
	for i := range 200 {
		var terms []string
		for j := 1; j <= 10; j++ {
			terms = append(terms, fmt.Sprintf("include:n%d.wide.test", i*10+j))
		}
		fmt.Fprintf(&b, "n%d.wide.test. TXT \"v=spf1 %s -all\"\n", i, strings.Join(terms, " "))
	}
	zone := dnstest.MustParseZone(b.String())
	a := &Analyzer{Resolver: zone}
	res, err := a.Analyze(context.Background(), "n0.wide.test")
	if err != nil {
		t.Fatal(err)
	}
	if q := len(zone.Queries()); q > 200 {
		t.Errorf("analysis issued %d queries", q)
	}
	if !slices.Contains(findingIDs(res.Findings), "MAIL-SPF-005") {
		t.Error("expected lookup limit finding")
	}
}
