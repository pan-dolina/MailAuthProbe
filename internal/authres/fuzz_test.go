package authres

import "testing"

func FuzzParseAuthenticationResults(f *testing.F) {
	for _, s := range []string{
		"mx.google.com; dkim=pass header.i=@example.com header.s=s1 header.b=AbCd; spf=pass (comment) smtp.mailfrom=\"a@example.com\"; dmarc=pass header.from=example.com",
		"example.org 1; none",
		"spf=pass smtp.mailfrom=example.com; dmarc=pass action=none header.from=example.com",
		"\"quoted id\"; dkim/1 = fail reason=\"x\\\"y\"",
		"(((; = ;",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		h, err := Parse(value)
		if err == nil {
			for _, r := range h.Results {
				if r.Method == "" || r.Result == "" {
					t.Fatalf("empty method or result: %+v", r)
				}
			}
		}
		_ = Compare(ParseAll([]string{value, value}), Computed{SPF: "pass", DMARC: "fail", DKIM: []ComputedDKIM{{Domain: "example.com", HeaderB: "Ab", Result: "pass"}}})
	})
}

func FuzzParseReceivedSPF(f *testing.F) {
	f.Add("pass (mx.example.org: domain of a@example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1; envelope-from=\"a@example.com\"; helo=mail.example.com;")
	f.Add("fail ((((")
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = ParseReceivedSPF(value)
	})
}
