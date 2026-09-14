package spf

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestIsSPF(t *testing.T) {
	tests := []struct {
		txt  string
		want bool
	}{
		{"v=spf1", true},
		{"v=spf1 -all", true},
		{"V=SPF1 -all", true},
		{"v=spf10 -all", false},
		{"v=spf1-all", false},
		{" v=spf1 -all", false},
		{"spf2.0/pra ip4:192.0.2.1", false},
		{"v=DMARC1; p=none", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsSPF(tt.txt); got != tt.want {
			t.Errorf("IsSPF(%q) = %v, want %v", tt.txt, got, tt.want)
		}
	}
}

func TestParseValid(t *testing.T) {
	type want struct {
		name      string
		qualifier Qualifier
		modifier  bool
		domain    string
		network   string
		cidr4     int
		cidr6     int
	}
	tests := []struct {
		record string
		terms  []want
	}{
		{"v=spf1", nil},
		{"v=spf1  -all  ", []want{{name: "all", qualifier: '-', cidr4: -1, cidr6: -1}}},
		{"v=spf1 +ALL", []want{{name: "all", qualifier: '+', cidr4: -1, cidr6: -1}}},
		{"v=spf1 ?all", []want{{name: "all", qualifier: '?', cidr4: -1, cidr6: -1}}},
		{"v=spf1 ~all", []want{{name: "all", qualifier: '~', cidr4: -1, cidr6: -1}}},
		{"v=spf1 include:_spf.example.com", []want{{name: "include", qualifier: '+', domain: "_spf.example.com", cidr4: -1, cidr6: -1}}},
		{"v=spf1 a", []want{{name: "a", qualifier: '+', cidr4: -1, cidr6: -1}}},
		{"v=spf1 a/24", []want{{name: "a", qualifier: '+', cidr4: 24, cidr6: -1}}},
		{"v=spf1 a//64", []want{{name: "a", qualifier: '+', cidr4: -1, cidr6: 64}}},
		{"v=spf1 -a:mail.example.com/24//64", []want{{name: "a", qualifier: '-', domain: "mail.example.com", cidr4: 24, cidr6: 64}}},
		{"v=spf1 mx:example.com//0", []want{{name: "mx", qualifier: '+', domain: "example.com", cidr4: -1, cidr6: 0}}},
		{"v=spf1 MX/32", []want{{name: "mx", qualifier: '+', cidr4: 32, cidr6: -1}}},
		{"v=spf1 ptr", []want{{name: "ptr", qualifier: '+', cidr4: -1, cidr6: -1}}},
		{"v=spf1 ?ptr:example.com", []want{{name: "ptr", qualifier: '?', domain: "example.com", cidr4: -1, cidr6: -1}}},
		{"v=spf1 ip4:192.0.2.1", []want{{name: "ip4", qualifier: '+', network: "192.0.2.1/32", cidr4: -1, cidr6: -1}}},
		{"v=spf1 ip4:192.0.2.77/24", []want{{name: "ip4", qualifier: '+', network: "192.0.2.0/24", cidr4: -1, cidr6: -1}}},
		{"v=spf1 ip4:0.0.0.0/0", []want{{name: "ip4", qualifier: '+', network: "0.0.0.0/0", cidr4: -1, cidr6: -1}}},
		{"v=spf1 ip6:2001:db8::1", []want{{name: "ip6", qualifier: '+', network: "2001:db8::1/128", cidr4: -1, cidr6: -1}}},
		{"v=spf1 -ip6:2001:DB8::/32", []want{{name: "ip6", qualifier: '-', network: "2001:db8::/32", cidr4: -1, cidr6: -1}}},
		{"v=spf1 ip6:::ffff:192.0.2.1/128", []want{{name: "ip6", qualifier: '+', network: "::ffff:192.0.2.1/128", cidr4: -1, cidr6: -1}}},
		{"v=spf1 exists:%{i}._spf.%{d}", []want{{name: "exists", qualifier: '+', domain: "%{i}._spf.%{d}", cidr4: -1, cidr6: -1}}},
		{"v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d}", []want{{name: "exists", qualifier: '+', domain: "%{ir}.%{l1r+-}._spf.%{d}", cidr4: -1, cidr6: -1}}},
		{"v=spf1 redirect=_spf.example.com", []want{{name: "redirect", modifier: true, domain: "_spf.example.com", cidr4: -1, cidr6: -1}}},
		{"v=spf1 exp=explain._spf.%{d} -all", []want{
			{name: "exp", modifier: true, domain: "explain._spf.%{d}", cidr4: -1, cidr6: -1},
			{name: "all", qualifier: '-', cidr4: -1, cidr6: -1},
		}},
		{"v=spf1 foo.bar=%{d}%%%_%- -all", []want{
			{name: "foo.bar", modifier: true, cidr4: -1, cidr6: -1},
			{name: "all", qualifier: '-', cidr4: -1, cidr6: -1},
		}},
		{"v=spf1 include:example.com.", []want{{name: "include", qualifier: '+', domain: "example.com.", cidr4: -1, cidr6: -1}}},
		{"v=spf1 include:xn--bcher-kva.example", []want{{name: "include", qualifier: '+', domain: "xn--bcher-kva.example", cidr4: -1, cidr6: -1}}},
	}
	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			rec, err := Parse(tt.record)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(rec.Terms) != len(tt.terms) {
				t.Fatalf("got %d terms, want %d: %+v", len(rec.Terms), len(tt.terms), rec.Terms)
			}
			for i, w := range tt.terms {
				g := rec.Terms[i]
				network := ""
				if g.Network.IsValid() {
					network = g.Network.String()
				}
				if g.Name != w.name || g.Qualifier != w.qualifier || g.Modifier != w.modifier ||
					g.Domain != w.domain || network != w.network || g.CIDR4 != w.cidr4 || g.CIDR6 != w.cidr6 {
					t.Errorf("term %d = {name:%s q:%q mod:%v dom:%q net:%q c4:%d c6:%d}, want %+v",
						i, g.Name, g.Qualifier, g.Modifier, g.Domain, network, g.CIDR4, g.CIDR6, w)
				}
			}
		})
	}
}

func TestParseModifierPointers(t *testing.T) {
	rec, err := Parse("v=spf1 ip4:192.0.2.1 exp=why.example.com a mx redirect=_spf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Redirect == nil || rec.Redirect.Domain != "_spf.example.com" {
		t.Errorf("Redirect = %+v", rec.Redirect)
	}
	if rec.Exp == nil || rec.Exp.Domain != "why.example.com" {
		t.Errorf("Exp = %+v", rec.Exp)
	}
	if rec.Redirect != &rec.Terms[4] {
		t.Error("Redirect does not point into Terms")
	}
	if got := len(rec.Directives()); got != 3 {
		t.Errorf("Directives() = %d", got)
	}
	if _, ok := rec.All(); ok {
		t.Error("All() found a term in a record without all")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		record string
		msg    string
	}{
		{"v=spf2 -all", `does not start with "v=spf1"`},
		{"v=spf1 -all:foo", "takes no arguments"},
		{"v=spf1 include", "requires a domain-spec"},
		{"v=spf1 include:", "requires a domain-spec"},
		{"v=spf1 include:localhost", "invalid domain-spec"},
		{"v=spf1 include:example.123", "invalid domain-spec"},
		{"v=spf1 include:%{d}com", "invalid domain-spec"},
		{"v=spf1 include:example..com", "invalid domain-spec"},
		{"v=spf1 exists", "requires a domain-spec"},
		{"v=spf1 ip4", "requires a network"},
		{"v=spf1 ip4:192.0.2", "invalid ip4 address"},
		{"v=spf1 ip4:192.0.2.1/33", "invalid prefix length"},
		{"v=spf1 ip4:192.0.2.1/024", "invalid prefix length"},
		{"v=spf1 ip4:192.000.2.1", "invalid ip4 address"},
		{"v=spf1 ip4:2001:db8::1", "requires an IPv4 address"},
		{"v=spf1 ip6:192.0.2.1", "requires an IPv6 address"},
		{"v=spf1 ip6:2001:db8::/129", "invalid prefix length"},
		{"v=spf1 ip6:fe80::1%eth0", "invalid ip6 address"},
		{"v=spf1 a/", "invalid ip4-cidr-length"},
		{"v=spf1 a/33", "invalid ip4-cidr-length"},
		{"v=spf1 a//129", "invalid ip6-cidr-length"},
		{"v=spf1 a:", "empty domain-spec"},
		{"v=spf1 mx:/24", "empty domain-spec"},
		{"v=spf1 ptr/24", "optional domain-spec"},
		{"v=spf1 foo", `unknown mechanism "foo"`},
		{"v=spf1 +", "missing mechanism name"},
		{"v=spf1 redirect=", "requires a domain-spec"},
		{"v=spf1 redirect=a.example redirect=b.example", "more than once"},
		{"v=spf1 exp=a.example exp=b.example", "more than once"},
		{"v=spf1 1foo=bar", "invalid modifier name"},
		{"v=spf1 include:%{x}.example.com", "unknown macro letter"},
		{"v=spf1 include:%{c}.example.com", `only allowed in "exp"`},
		{"v=spf1 include:%{d0}.example.com", "must be non-zero"},
		{"v=spf1 include:%{d.example.com", "unterminated"},
		{"v=spf1 include:%x.example.com", "invalid macro escape"},
		{"v=spf1 include:example.com%", `dangling "%"`},
		{"v=spf1 include:%{d;}.example.com", "invalid macro delimiter"},
		{"v=spf1 -all\t", "invalid character"},
		{"v=spf1 ip4:192.0.2.1\x00", "invalid character"},
	}
	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			_, err := Parse(tt.record)
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("err = %v, want *SyntaxError", err)
			}
			if !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("error %q does not contain %q", err, tt.msg)
			}
		})
	}
}

func TestParseCollectsAllErrors(t *testing.T) {
	rec, err := Parse("v=spf1 ip4:192.0.2.1 bogus ip4:1.2.3 include:example.com -all")
	var se *SyntaxError
	if !errors.As(err, &se) || len(se.Errors) != 2 {
		t.Fatalf("err = %v", err)
	}
	if rec == nil || len(rec.Terms) != 3 {
		t.Fatalf("partial record = %+v", rec)
	}
}

func TestParseExpAllowsExplanationMacros(t *testing.T) {
	if _, err := Parse("v=spf1 exp=%{c}.%{r}.%{t}.example.com -all"); err != nil {
		t.Fatal(err)
	}
}

func TestTermCountsLookup(t *testing.T) {
	rec, err := Parse("v=spf1 all include:a.example a mx ptr ip4:192.0.2.1 ip6:::1 exists:b.example redirect=c.example exp=d.example x=y")
	if err != nil {
		t.Fatal(err)
	}
	var counted []string
	for _, term := range rec.Terms {
		if term.CountsLookup() {
			counted = append(counted, term.Name)
		}
	}
	if got := strings.Join(counted, ","); got != "include,a,mx,ptr,exists,redirect" {
		t.Errorf("counted = %s", got)
	}
}

func TestQualifierResult(t *testing.T) {
	tests := map[Qualifier]Result{
		QualifierPass: ResultPass, QualifierFail: ResultFail,
		QualifierSoftFail: ResultSoftFail, QualifierNeutral: ResultNeutral,
	}
	for q, want := range tests {
		if got := q.Result(); got != want {
			t.Errorf("%c.Result() = %s, want %s", q, got, want)
		}
	}
}

func TestParseNetworkMasksHostBits(t *testing.T) {
	rec, err := Parse("v=spf1 ip4:198.51.100.200/25")
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.Terms[0].Network; got != netip.MustParsePrefix("198.51.100.128/25") {
		t.Errorf("network = %s", got)
	}
}
