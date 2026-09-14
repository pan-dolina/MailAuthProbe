package tlsrpt

import (
	"context"
	"slices"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/pan-dolina/mailauthprobe/internal/findings"
)

func TestParse(t *testing.T) {
	r, err := Parse("v=TLSRPTv1; rua=mailto:tls@example.com, https://reports.example.com/tlsrpt; ext=1")
	if err != nil || len(r.RUA) != 2 || len(r.InvalidURIs) != 0 || r.Extensions["ext"] != "1" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = Parse("v=TLSRPTv1;rua=mailto:not-an-address,ftp://x.example,https://user:pw@x.example/,mailto:ok@example.com")
	if err != nil || len(r.RUA) != 1 || len(r.InvalidURIs) != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{"v=TLSRPTv2; rua=mailto:a@example.com", "rua=mailto:a@example.com", "v=TLSRPTv1;", "v=TLSRPTv1; rua=mailto:a@example.com; rua=mailto:b@example.com", "v=TLSRPTv1; junk"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestAssess(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		mtaSTS   bool
		want     []string
		severity findings.Severity
		wantErr  bool
	}{
		{"valid", `_smtp._tls.example.com. TXT "v=TLSRPTv1; rua=mailto:tls@example.com"`, true, []string{"MAIL-TLSRPT-004"}, findings.SeverityPass, false},
		{"missing with MTA-STS", `example.com. TXT "x"`, true, []string{"MAIL-TLSRPT-001"}, findings.SeverityLow, false},
		{"missing without MTA-STS", `example.com. TXT "x"`, false, []string{"MAIL-TLSRPT-001"}, findings.SeverityInfo, false},
		{"multiple", "_smtp._tls.example.com. TXT \"v=TLSRPTv1; rua=mailto:a@example.com\"\n_smtp._tls.example.com. TXT \"v=TLSRPTv1; rua=mailto:b@example.com\"", true, []string{"MAIL-TLSRPT-002"}, findings.SeverityMedium, false},
		{"invalid", `_smtp._tls.example.com. TXT "v=TLSRPTv1; ruf=mailto:a@example.com"`, true, []string{"MAIL-TLSRPT-002"}, findings.SeverityMedium, false},
		{"only invalid uris", `_smtp._tls.example.com. TXT "v=TLSRPTv1; rua=tls@example.com"`, true, []string{"MAIL-TLSRPT-003"}, findings.SeverityHigh, false},
		{"some invalid uris", `_smtp._tls.example.com. TXT "v=TLSRPTv1; rua=tls@example.com,mailto:tls@example.com"`, true, []string{"MAIL-TLSRPT-003"}, findings.SeverityMedium, false},
		{"lookup failure", `_smtp._tls.example.com. SERVFAIL`, true, []string{"MAIL-DNS-001"}, findings.SeverityHigh, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Assess(context.Background(), dnstest.MustParseZone(tt.zone), "example.com", tt.mtaSTS)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			var ids []string
			for _, f := range a.Findings {
				ids = append(ids, f.ID)
			}
			if !slices.Equal(ids, tt.want) || findings.Max(a.Findings) != tt.severity {
				t.Errorf("findings = %v (max %v), want %v (%v)", ids, findings.Max(a.Findings), tt.want, tt.severity)
			}
		})
	}
}
