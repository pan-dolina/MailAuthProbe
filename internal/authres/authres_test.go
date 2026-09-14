package authres

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	h, err := Parse(`mx.google.com;
       dkim=pass header.i=@example.com header.s=s1 header.b=AbCdEf12;
       arc=none (no signatures found);
       spf=pass (google.com: domain of bounce@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom="bounce@example.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com`)
	if err != nil {
		t.Fatal(err)
	}
	if h.AuthServID != "mx.google.com" || len(h.Results) != 4 {
		t.Fatalf("header = %+v", h)
	}
	dkim := h.ByMethod("DKIM")
	if len(dkim) != 1 || dkim[0].Result != "pass" || dkim[0].Prop("header.i") != "@example.com" || dkim[0].Prop("header.b") != "AbCdEf12" {
		t.Errorf("dkim = %+v", dkim)
	}
	if spf := h.ByMethod("spf"); spf[0].Prop("smtp.mailfrom") != "bounce@example.com" {
		t.Errorf("spf = %+v", spf)
	}
	if d := h.ByMethod("dmarc"); d[0].Prop("header.from") != "example.com" {
		t.Errorf("dmarc = %+v", d)
	}
}

func TestParseVariants(t *testing.T) {
	tests := []struct {
		name  string
		value string
		check func(*testing.T, *Header)
	}{
		{"none", "example.org 1; none", func(t *testing.T, h *Header) {
			if !h.None || h.Version != "1" || len(h.Results) != 0 {
				t.Errorf("%+v", h)
			}
		}},
		{"quoted authserv-id and reason", `"mx.example.org"; dkim=fail reason="signature verification failed" header.d=example.com`, func(t *testing.T, h *Header) {
			r := h.Results[0]
			if h.AuthServID != "mx.example.org" || r.Reason != "signature verification failed" || r.Prop("header.d") != "example.com" {
				t.Errorf("%+v", h)
			}
		}},
		{"method version and spaces around equals", "mx.example.org; dkim/1 = pass header.d = example.com", func(t *testing.T, h *Header) {
			r := h.Results[0]
			if r.Method != "dkim" || r.Version != "1" || r.Result != "pass" || r.Prop("header.d") != "example.com" {
				t.Errorf("%+v", r)
			}
		}},
		{"microsoft", "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.com; dkim=pass (signature was verified) header.d=example.com;dmarc=pass action=none header.from=example.com;compauth=pass reason=100", func(t *testing.T, h *Header) {
			// Exchange Online omits the authserv-id.
			if h.AuthServID != "" || len(h.Results) != 4 || h.Results[2].Prop("action") != "none" || h.Results[3].Reason != "100" {
				t.Errorf("header = %+v", h)
			}
		}},
		{"comment with semicolon and parens", "mx.example.org; spf=fail (reason: not (really) permitted; see policy) smtp.mailfrom=a@example.com", func(t *testing.T, h *Header) {
			if len(h.Results) != 1 || h.Results[0].Prop("smtp.mailfrom") != "a@example.com" {
				t.Errorf("%+v", h.Results)
			}
		}},
		{"trailing semicolon", "mx.example.org; spf=none;", func(t *testing.T, h *Header) {
			if len(h.Results) != 1 {
				t.Errorf("%+v", h.Results)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := Parse(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, h)
		})
	}
}

func TestParseErrors(t *testing.T) {
	for _, v := range []string{
		"",
		"   ",
		"mx.example.org; dkim",
		"mx.example.org; dkim=pass header.d",
		"mx.example.org; dkim=pass (unterminated",
		`mx.example.org; dkim=pass header.d="unterminated`,
		"mx.example.org extra words; spf=pass",
		"mx.example.org; spf=pass " + strings.Repeat("(", 40) + strings.Repeat(")", 40),
	} {
		if h, err := Parse(v); err == nil {
			t.Errorf("Parse(%q) = %+v, want error", v, h)
		}
	}
}

func TestParseReceivedSPF(t *testing.T) {
	r, err := ParseReceivedSPF(`pass (mx.example.org: domain of bounce@example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1; envelope-from="bounce@example.com"; helo=mail.example.com; receiver=mx.example.org; identity=mailfrom;`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Result != "pass" || r.Params["client-ip"] != "192.0.2.1" || r.Params["envelope-from"] != "bounce@example.com" ||
		r.Params["helo"] != "mail.example.com" || !strings.Contains(r.Comment, "designates") {
		t.Errorf("%+v", r)
	}
	if r, err := ParseReceivedSPF("SoftFail client-ip=203.0.113.1"); err != nil || r.Result != "softfail" || r.Params["client-ip"] != "203.0.113.1" {
		t.Errorf("%+v %v", r, err)
	}
	for _, bad := range []string{"", "maybe client-ip=1.2.3.4", "pass (unterminated"} {
		if _, err := ParseReceivedSPF(bad); err == nil {
			t.Errorf("ParseReceivedSPF(%q) succeeded", bad)
		}
	}
}
