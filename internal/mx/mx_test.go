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
