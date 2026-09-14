package arc

import (
	"strings"
	"testing"

	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
)

func parse(t *testing.T, headers ...string) *mailparser.Message {
	t.Helper()
	m, err := mailparser.ParseBytes([]byte(strings.Join(headers, "\r\n")+"\r\n\r\nbody\r\n"), mailparser.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSummarize(t *testing.T) {
	set := func(i, cv, d string) []string {
		return []string{
			"ARC-Seal: i=" + i + "; a=rsa-sha256; cv=" + cv + "; d=" + d + "; s=arc; b=AAAA",
			"ARC-Message-Signature: i=" + i + "; a=rsa-sha256; d=" + d + "; s=arc; h=from; bh=AA; b=AA",
			"ARC-Authentication-Results: i=" + i + "; " + d + "; spf=pass",
		}
	}
	tests := []struct {
		name    string
		headers []string
		valid   bool
		id      string
	}{
		{"none", []string{"From: a@example.com"}, false, ""},
		{"single valid", append(set("1", "none", "lists.example"), "From: a@example.com"), true, "MAIL-ARC-001"},
		{"two instances", append(append(set("2", "pass", "fwd.example"), set("1", "none", "lists.example")...), "From: a@example.com"), true, "MAIL-ARC-001"},
		{"cv fail", append(append(set("2", "fail", "fwd.example"), set("1", "none", "lists.example")...), "From: a@example.com"), true, "MAIL-ARC-002"},
		{"missing instance 1", append(set("2", "pass", "fwd.example"), "From: a@example.com"), false, "MAIL-ARC-003"},
		{"incomplete", []string{"ARC-Seal: i=1; cv=none; d=x.example", "From: a@example.com"}, false, "MAIL-ARC-003"},
		{"bad instance", append(set("0", "none", "x.example"), "From: a@example.com"), false, "MAIL-ARC-003"},
		{"duplicate", append(append(set("1", "none", "x.example"), set("1", "none", "y.example")...), "From: a@example.com"), false, "MAIL-ARC-003"},
		{"instance 1 with pass", append(set("1", "pass", "x.example"), "From: a@example.com"), false, "MAIL-ARC-003"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Summarize(parse(t, tt.headers...))
			if tt.id == "" {
				if s != nil {
					t.Errorf("summary for message without ARC: %+v", s)
				}
				return
			}
			if s.Valid != tt.valid || len(s.Findings) != 1 || s.Findings[0].ID != tt.id {
				t.Errorf("valid = %v, findings = %+v, problems = %v", s.Valid, s.Findings, s.Problems)
			}
		})
	}
}
