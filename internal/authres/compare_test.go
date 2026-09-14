package authres

import (
	"slices"
	"strings"
	"testing"
)

func compareIDs(values []string, c Computed) ([]string, []string) {
	fs := Compare(ParseAll(values), c)
	var ids, ev []string
	for _, f := range fs {
		ids = append(ids, f.ID)
		ev = append(ev, f.Evidence...)
	}
	slices.Sort(ids)
	return ids, ev
}

func TestCompare(t *testing.T) {
	computed := Computed{
		DKIMEvaluated: true,
		SPF:           "pass",
		DKIM:          []ComputedDKIM{{Domain: "example.com", Selector: "s1", HeaderB: "AbCdEfGhIjKl", Result: "pass"}},
		DMARC:         "pass",
	}
	tests := []struct {
		name     string
		values   []string
		computed Computed
		ids      []string
		evidence string
	}{
		{"agree", []string{"mx.example.org; spf=pass smtp.mailfrom=a@example.com; dkim=pass header.d=example.com header.b=AbCdEfGh; dmarc=pass"},
			computed, []string{"MAIL-AR-003"}, "dkim d=example.com=pass"},
		{"none header", nil, computed, []string{"MAIL-AR-005"}, ""},
		{"dmarc mismatch", []string{"mx.example.org; dmarc=pass header.from=example.com"},
			Computed{DMARC: "fail"}, []string{"MAIL-AR-002"}, "dmarc: header says pass, MailAuthProbe computed fail"},
		{"inferred spf noted", []string{"mx.example.org; spf=pass"},
			Computed{SPF: "fail", SPFInferred: true}, []string{"MAIL-AR-002"}, "inferred"},
		{"dkim matched by domain and selector", []string{"mx.example.org; dkim=fail header.d=example.com header.s=s1"},
			computed, []string{"MAIL-AR-002"}, "dkim d=example.com: header says fail"},
		{"claimed signature absent", []string{"mx.example.org; dkim=pass header.d=bank.example"},
			Computed{DKIMEvaluated: true}, []string{"MAIL-AR-002"}, "not present in the message"},
		{"dkim not evaluated", []string{"mx.example.org; dkim=pass header.d=bank.example"},
			Computed{}, nil, ""},
		{"local temperror is not a disagreement", []string{"mx.example.org; spf=pass; dmarc=pass"},
			Computed{SPF: "temperror", DMARC: "temperror"}, nil, ""},
		{"short header.b does not match", []string{"mx.example.org; dkim=pass header.d=other.example header.b=Ab"},
			Computed{DKIMEvaluated: true, DKIM: []ComputedDKIM{{Domain: "example.com", HeaderB: "AbCdEfGhIjKl", Result: "fail"}}}, []string{"MAIL-AR-002"}, "not present"},
		{"conflict under same authserv-id", []string{
			"mx.example.org; dkim=pass header.d=example.com; spf=pass",
			"mx.example.org; dkim=fail header.d=example.com; spf=pass",
		}, computed, []string{"MAIL-AR-001", "MAIL-AR-003"}, ""},
		{"different servers may disagree", []string{
			"mx.example.org; spf=pass",
			"relay.example.net; spf=fail",
		}, Computed{SPF: "pass"}, []string{"MAIL-AR-003"}, ""},
		{"unparseable is reported and skipped", []string{
			"mx.example.org; spf",
			"relay.example.net; spf=pass",
		}, Computed{SPF: "pass"}, []string{"MAIL-AR-003", "MAIL-AR-004"}, ""},
		{"hardfail equals fail", []string{"mx.example.org; spf=hardfail"}, Computed{SPF: "fail"}, []string{"MAIL-AR-003"}, ""},
		{"nothing comparable", []string{"mx.example.org; arc=none"}, computed, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, ev := compareIDs(tt.values, tt.computed)
			if !slices.Equal(ids, tt.ids) {
				t.Errorf("findings = %v, want %v", ids, tt.ids)
			}
			if tt.evidence != "" && !strings.Contains(strings.Join(ev, "\n"), tt.evidence) {
				t.Errorf("evidence %q does not contain %q", ev, tt.evidence)
			}
		})
	}
}
