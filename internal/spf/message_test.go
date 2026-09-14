package spf

import (
	"context"
	"slices"
	"testing"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
)

func TestCheckMessage(t *testing.T) {
	zone := dnstest.MustParseZone(`
example.test.        TXT "v=spf1 ip4:192.0.2.0/24 -all"
soft.test.           TXT "v=spf1 ~all"
mail.example.test.   TXT "v=spf1 a -all"
mail.example.test.   A   192.0.2.10
loop.test.           TXT "v=spf1 include:loop.test -all"
`)
	flag := func(v string) *Input { return &Input{Value: v, Source: SourceFlag} }
	rcvd := func(v string) *Input { return &Input{Value: v, Source: SourceReceived, Inferred: true} }
	tests := []struct {
		name   string
		in     MessageInputs
		result Result
		domain string
		ids    []string
	}{
		{"pass", MessageInputs{IP: flag("192.0.2.10"), MailFrom: flag("bounce@example.test"), HELO: flag("mail.example.test")}, ResultPass, "example.test", []string{"MAIL-SPF-030"}},
		{"fail inferred", MessageInputs{IP: rcvd("203.0.113.66"), MailFrom: &Input{Value: "x@example.test", Source: SourceReturnPath, Inferred: true}}, ResultFail, "example.test", []string{"MAIL-SPF-031", "MAIL-SPF-035"}},
		{"softfail", MessageInputs{IP: flag("203.0.113.66"), MailFrom: flag("x@soft.test")}, ResultSoftFail, "soft.test", []string{"MAIL-SPF-032"}},
		{"none", MessageInputs{IP: flag("203.0.113.66"), MailFrom: flag("x@nospf.test")}, ResultNone, "nospf.test", []string{"MAIL-SPF-033"}},
		{"null sender uses HELO", MessageInputs{IP: flag("192.0.2.10"), HELO: flag("mail.example.test"), NullSender: true}, ResultPass, "mail.example.test", []string{"MAIL-SPF-030"}},
		{"permerror loop is high", MessageInputs{IP: flag("192.0.2.10"), MailFrom: flag("x@loop.test")}, ResultPermError, "loop.test", []string{"MAIL-SPF-034"}},
		{"no ip", MessageInputs{MailFrom: flag("x@example.test")}, "", "", []string{"MAIL-SPF-036"}},
		{"bad ip", MessageInputs{IP: flag("not-an-ip"), MailFrom: flag("x@example.test")}, "", "", []string{"MAIL-SPF-036"}},
		{"no identity", MessageInputs{IP: flag("192.0.2.10")}, "", "", []string{"MAIL-SPF-036"}},
		{"null sender without helo", MessageInputs{IP: flag("192.0.2.10"), NullSender: true}, "", "", []string{"MAIL-SPF-036"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Checker{Resolver: zone}
			mc := c.CheckMessage(context.Background(), tt.in)
			if mc.Result != tt.result || mc.Domain != tt.domain {
				t.Errorf("result = %q for %q, want %q for %q", mc.Result, mc.Domain, tt.result, tt.domain)
			}
			var ids []string
			for _, f := range mc.Findings {
				ids = append(ids, f.ID)
			}
			slices.Sort(ids)
			if !slices.Equal(ids, tt.ids) {
				t.Errorf("findings = %v, want %v", ids, tt.ids)
			}
			if tt.name == "permerror loop is high" && mc.Findings[0].Severity.String() != "high" {
				t.Errorf("severity = %v", mc.Findings[0].Severity)
			}
		})
	}
}
