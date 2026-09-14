package mx

import (
	"context"
	"slices"
	"testing"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
)

func ids(fs []findings.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	slices.Sort(out)
	return out
}

func TestAssessHealthyDomain(t *testing.T) {
	zone := dnstest.MustParseZone(`
example.test.     MX   20 mx2.example.test.
example.test.     MX   10 mx1.example.test.
mx1.example.test. A    192.0.2.10
mx1.example.test. AAAA 2001:db8::10
mx2.example.test. A    192.0.2.20
`)
	res, err := Assess(context.Background(), zone, "Example.Test.")
	if err != nil {
		t.Fatal(err)
	}
	if res.Domain != "example.test" || len(res.Hosts) != 2 || res.Hosts[0].Name != "mx1.example.test" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if got := ids(res.Findings); !slices.Equal(got, []string{"MAIL-MX-015"}) {
		t.Errorf("findings = %v", got)
	}
}

func TestAssessEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		zone    string
		domain  string
		want    []string
		wantErr bool
		check   func(t *testing.T, res *Result)
	}{
		{
			name:   "nxdomain",
			zone:   `other.test. A 192.0.2.1`,
			domain: "missing.test",
			want:   []string{"MAIL-MX-003"},
		},
		{
			name:   "implicit MX",
			zone:   `example.test. A 192.0.2.1`,
			domain: "example.test",
			want:   []string{"MAIL-MX-001"},
			check: func(t *testing.T, res *Result) {
				if !res.Implicit || len(res.Hosts) != 1 {
					t.Errorf("implicit = %v, hosts = %v", res.Implicit, res.Hosts)
				}
			},
		},
		{
			name:   "no MX and no address",
			zone:   `example.test. TXT "v=spf1 -all"`,
			domain: "example.test",
			want:   []string{"MAIL-MX-002"},
		},
		{
			name:   "null MX",
			zone:   `example.test. MX 0 .`,
			domain: "example.test",
			want:   []string{"MAIL-MX-004"},
			check: func(t *testing.T, res *Result) {
				if !res.NullMX {
					t.Error("NullMX not set")
				}
			},
		},
		{
			name:   "null MX with non-zero preference",
			zone:   `example.test. MX 10 .`,
			domain: "example.test",
			want:   []string{"MAIL-MX-004", "MAIL-MX-006"},
		},
		{
			name: "null MX mixed with real MX",
			zone: `
example.test.    MX 0 .
example.test.    MX 10 mx.example.test.
mx.example.test. A 192.0.2.1
`,
			domain: "example.test",
			want:   []string{"MAIL-MX-005", "MAIL-MX-013", "MAIL-MX-014"},
		},
		{
			name: "duplicate host with different preferences",
			zone: `
example.test.     MX 10 mx1.example.test.
example.test.     MX 20 mx1.example.test.
example.test.     MX 30 mx2.example.test.
mx1.example.test. AAAA 2001:db8::1
mx2.example.test. AAAA 2001:db8::2
`,
			domain: "example.test",
			want:   []string{"MAIL-MX-007"},
			check: func(t *testing.T, res *Result) {
				if len(res.Hosts) != 2 {
					t.Errorf("duplicates should be collapsed, got %d hosts", len(res.Hosts))
				}
			},
		},
		{
			name: "MX pointing to CNAME",
			zone: `
example.test.       MX    10 alias.example.test.
alias.example.test. CNAME real.example.test.
real.example.test.  A     192.0.2.7
real.example.test.  AAAA  2001:db8::7
`,
			domain: "example.test",
			want:   []string{"MAIL-MX-009", "MAIL-MX-014"},
			check: func(t *testing.T, res *Result) {
				if res.Hosts[0].CNAME != "real.example.test" || len(res.Hosts[0].IPv4) != 1 {
					t.Errorf("host = %+v", res.Hosts[0])
				}
			},
		},
		{
			name:   "MX target is an IP literal",
			zone:   `example.test. MX 10 192.0.2.25`,
			domain: "example.test",
			want:   []string{"MAIL-MX-008"},
		},
		{
			name: "one of two hosts has no addresses",
			zone: `
example.test.     MX 10 mx1.example.test.
example.test.     MX 20 mx2.example.test.
mx1.example.test. A 192.0.2.1
mx2.example.test. TXT "exists without addresses"
`,
			domain: "example.test",
			want:   []string{"MAIL-MX-010", "MAIL-MX-013"},
			check: func(t *testing.T, res *Result) {
				if sev := findingSeverity(res, "MAIL-MX-010"); sev != findings.SeverityMedium {
					t.Errorf("partial outage severity = %v, want medium", sev)
				}
			},
		},
		{
			name: "all hosts unresolvable",
			zone: `
example.test. MX 10 gone.example.test.
example.test. MX 20 gone2.example.test.
`,
			domain: "example.test",
			want:   []string{"MAIL-MX-010", "MAIL-MX-010"},
			check: func(t *testing.T, res *Result) {
				if sev := findingSeverity(res, "MAIL-MX-010"); sev != findings.SeverityHigh {
					t.Errorf("total outage severity = %v, want high", sev)
				}
				if res.Hosts[0].Error == "" {
					t.Error("host error not recorded")
				}
			},
		},
		{
			name: "private and loopback addresses",
			zone: `
example.test.    MX   10 mx.example.test.
mx.example.test. A    10.0.0.25
mx.example.test. AAAA ::1
`,
			domain: "example.test",
			want:   []string{"MAIL-MX-011", "MAIL-MX-014"},
		},
		{
			name: "invalid host name",
			zone: `
example.test.     MX 10 _mx.example.test.
_mx.example.test. A  192.0.2.1
`,
			domain: "example.test",
			want:   []string{"MAIL-MX-013", "MAIL-MX-014", "MAIL-MX-016"},
		},
		{
			name: "temporary failure resolving host",
			zone: `
example.test.       MX 10 flaky.example.test.
example.test.       MX 20 mx.example.test.
flaky.example.test. SERVFAIL A
mx.example.test.    A 192.0.2.1
mx.example.test.    AAAA 2001:db8::1
`,
			domain:  "example.test",
			want:    []string{"MAIL-MX-012"},
			wantErr: true,
		},
		{
			name:    "MX lookup times out",
			zone:    `example.test. TIMEOUT MX`,
			domain:  "example.test",
			want:    []string{"MAIL-DNS-001"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := dnstest.MustParseZone(tt.zone)
			res, err := Assess(context.Background(), zone, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if got := ids(res.Findings); !slices.Equal(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
				for _, f := range res.Findings {
					t.Logf("  %s %s: %s", f.ID, f.Subject, f.Description)
				}
			}
			if tt.check != nil {
				tt.check(t, res)
			}
		})
	}
}

func TestAssessLimitsHostLookups(t *testing.T) {
	zone := dnstest.NewZone()
	for i := range MaxHosts + 5 {
		name := "mx" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".example.test."
		if err := zone.AddLine("example.test. MX 10 " + name); err != nil {
			t.Fatal(err)
		}
		if err := zone.AddLine(name + " A 192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Assess(context.Background(), zone, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != MaxHosts+5 {
		t.Errorf("hosts = %d", len(res.Hosts))
	}
	// 1 MX query + 3 per checked host (CNAME, A, AAAA).
	if got, want := len(zone.Queries()), 1+3*MaxHosts; got != want {
		t.Errorf("queries = %d, want %d", got, want)
	}
	if !slices.Contains(ids(res.Findings), "MAIL-MX-017") {
		t.Error("missing MAIL-MX-017")
	}
}

func findingSeverity(res *Result, id string) findings.Severity {
	for _, f := range res.Findings {
		if f.ID == id {
			return f.Severity
		}
	}
	return 0
}
