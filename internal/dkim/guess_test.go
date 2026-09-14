package dkim

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/pan-dolina/mailauthprobe/internal/findings"
	"github.com/pan-dolina/mailauthprobe/internal/mailprovider"
)

func TestAssessGuessesProviderSelectors(t *testing.T) {
	testKeys(t)
	zone := dnstest.MustParseZone(`
google._domainkey.gw.example.        TXT   "v=DKIM1; k=rsa; p=` + rsa2048 + `"
selector1._domainkey.m365.example.   CNAME selector1-m365-example._domainkey.tenant.onmicrosoft.com.
selector1-m365-example._domainkey.tenant.onmicrosoft.com. TXT "v=DKIM1; k=rsa; p=` + rsa1024 + `"
selector2._domainkey.m365.example.   CNAME selector2-m365-example._domainkey.tenant.onmicrosoft.com.
s1._domainkey.flaky.example.         SERVFAIL
`)
	google := mailprovider.Detect([]string{"aspmx.l.google.com"}, nil)
	m365 := mailprovider.Detect(nil, []string{"spf.protection.outlook.com"})
	sendgrid := mailprovider.Detect(nil, []string{"sendgrid.net"})
	ses := mailprovider.Detect(nil, []string{"amazonses.com"})

	tests := []struct {
		name      string
		domain    string
		selectors []string
		providers []mailprovider.Match
		wantIDs   []string
		wantDesc  []string
		notDesc   string
		wantErr   bool
		queries   int
	}{
		{
			name: "no providers", domain: "gw.example",
			wantIDs: []string{"MAIL-DKIM-001"}, wantDesc: []string{"--dkim-selector"},
		},
		{
			name: "google default found", domain: "gw.example", providers: google,
			wantIDs: []string{"MAIL-DKIM-012", "MAIL-DKIM-016"}, wantDesc: []string{"Google Workspace (google)"}, queries: 1,
		},
		{
			name: "key behind CNAME, second selector dangling", domain: "m365.example", providers: m365,
			wantIDs: []string{"MAIL-DKIM-006", "MAIL-DKIM-016"}, wantDesc: []string{"Microsoft 365 (selector1)"}, queries: 2,
		},
		{
			name: "defaults missing", domain: "gw.example", providers: slices.Concat(google, sendgrid, ses),
			wantIDs: []string{"MAIL-DKIM-012", "MAIL-DKIM-016"},
			wantDesc: []string{
				"Google Workspace (google)",
				"No DKIM key was found under the documented default selectors of SendGrid (s1, s2)",
				"Amazon SES (Easy DKIM)",
			},
			queries: 3,
		},
		{
			name: "nothing found", domain: "other.example", providers: slices.Concat(google, ses),
			wantIDs:  []string{"MAIL-DKIM-001"},
			wantDesc: []string{"Google Workspace (google); the domain may use custom selectors", "Amazon SES", "--dkim-selector"},
			queries:  1,
		},
		{
			name: "lookup failure is not reported as a missing key", domain: "flaky.example", providers: sendgrid,
			wantIDs: []string{"MAIL-DKIM-001", "MAIL-DNS-001"}, notDesc: "No DKIM key was found", wantErr: true, queries: 2,
		},
		{
			name: "explicit selectors disable guessing", domain: "gw.example", selectors: []string{"other"}, providers: google,
			wantIDs: []string{"MAIL-DKIM-002"}, queries: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone.ResetQueries()
			a, err := Assess(context.Background(), zone, tt.domain, tt.selectors, tt.providers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			var got []string
			var desc string
			for _, f := range a.Findings {
				got = append(got, f.ID)
				if f.ID == findings.DKIMNoSelector.ID || f.ID == findings.DKIMSelectorsGuessed.ID {
					desc = f.Description
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.wantIDs) {
				t.Errorf("findings = %v, want %v", got, tt.wantIDs)
			}
			for _, want := range tt.wantDesc {
				if !strings.Contains(desc, want) {
					t.Errorf("description %q does not contain %q", desc, want)
				}
			}
			if n := len(zone.Queries()); n != tt.queries {
				t.Errorf("queries = %d, want %d", n, tt.queries)
			}
			if tt.notDesc != "" && strings.Contains(desc, tt.notDesc) {
				t.Errorf("description %q contains %q", desc, tt.notDesc)
			}
		})
	}
}

func TestAssessGuessedSelectorOrigin(t *testing.T) {
	zone := dnstest.MustParseZone(`mail._domainkey.example.com. TXT "v=DKIM1; p="`)
	providers := mailprovider.Detect(nil, []string{"spf.brevo.com", "_spf.yandex.net"})
	a, _ := Assess(context.Background(), zone, "example.com", nil, providers)
	var got []string
	for _, s := range a.Selectors {
		got = append(got, s.Selector+"/"+s.Provider+"/"+s.Error)
	}
	// "mail" is a default of both Brevo and Yandex 360; it is queried once
	// and attributed to the first provider.
	want := []string{"brevo1/Brevo/" + NoKeyRecord, "brevo2/Brevo/" + NoKeyRecord, "mail/Brevo/"}
	if !slices.Equal(got, want) {
		t.Errorf("selectors = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(a.Providers, providers) {
		t.Errorf("providers = %+v", a.Providers)
	}
}

func TestAssessGuessLimit(t *testing.T) {
	var providers []mailprovider.Match
	for i := range MaxGuessedSelectors + 5 {
		providers = append(providers, mailprovider.Match{Provider: "p", DKIMSelectors: []string{"s" + strings.Repeat("x", i)}})
	}
	zone := dnstest.NewZone()
	a, _ := Assess(context.Background(), zone, "example.com", nil, providers)
	if len(a.Selectors) != MaxGuessedSelectors || len(zone.Queries()) != MaxGuessedSelectors {
		t.Errorf("selectors = %d, queries = %d", len(a.Selectors), len(zone.Queries()))
	}
}
