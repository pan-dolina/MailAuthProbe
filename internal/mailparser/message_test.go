package mailparser

import (
	"slices"
	"strings"
	"testing"
)

func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

func defectKinds(m *Message) []DefectKind {
	var out []DefectKind
	for _, d := range m.Defects {
		out = append(out, d.Kind)
	}
	return out
}

func TestParseHeaders(t *testing.T) {
	raw := crlf("From: Alice <alice@example.com>\nSubject: hello\n world\nTo: bob@example.net,\n\tcarol@example.org\nX-Empty:\n\nBody line 1\nBody line 2\n")
	m, err := ParseBytes([]byte(raw), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Headers) != 4 {
		t.Fatalf("headers = %d", len(m.Headers))
	}
	if v, _ := m.First("subject"); v != "hello world" {
		t.Errorf("Subject = %q", v)
	}
	if v, _ := m.First("TO"); v != "bob@example.net,\tcarol@example.org" {
		t.Errorf("To = %q", v)
	}
	if got := string(m.Get("To")[0].Raw); got != "To: bob@example.net,\r\n\tcarol@example.org\r\n" {
		t.Errorf("raw To = %q", got)
	}
	if v, ok := m.First("x-empty"); !ok || v != "" {
		t.Errorf("X-Empty = %q, %v", v, ok)
	}
	if string(m.Body) != "Body line 1\r\nBody line 2\r\n" || !m.HasBody {
		t.Errorf("body = %q", m.Body)
	}
	if m.HeaderSize+len(m.Body) != len(raw) {
		t.Errorf("header size %d + body %d != %d", m.HeaderSize, len(m.Body), len(raw))
	}
	if len(m.Defects) != 0 {
		t.Errorf("defects = %v", m.Defects)
	}
	// Raw header bytes must reproduce the header section exactly.
	var rebuilt strings.Builder
	for _, h := range m.Headers {
		rebuilt.Write(h.Raw)
	}
	if rebuilt.String()+"\r\n" != raw[:m.HeaderSize] {
		t.Error("raw headers do not reproduce the header section")
	}
}

func TestParseRepeatedHeadersKeepOrder(t *testing.T) {
	m, _ := ParseBytes([]byte(crlf("Received: one\nReceived: two\nreceived: three\n\n")), Options{})
	var got []string
	for _, h := range m.Get("Received") {
		got = append(got, h.Value)
	}
	if !slices.Equal(got, []string{"one", "two", "three"}) {
		t.Errorf("got %v", got)
	}
	if m.HasBody {
		t.Errorf("empty body reported as present: %q", m.Body)
	}
}

func TestParseDefects(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []DefectKind
	}{
		{"bare LF", "From: a@example.com\n\nbody\n", []DefectKind{DefectBareLF}},
		{"mixed endings", "From: a@example.com\r\nTo: b@example.com\n\r\nbody\r\n", []DefectKind{DefectMixedLineEndings}},
		{"leading continuation", crlf(" folded\nFrom: a@example.com\n\n"), []DefectKind{DefectLeadingContinuation}},
		{"whitespace before colon", crlf("Subject : hi\n\n"), []DefectKind{DefectWhitespaceBeforeColon}},
		{"no colon starts body", crlf("From: a@example.com\nthis is not a header\nmore\n"), []DefectKind{DefectMalformedHeaderLine, DefectNoBodySeparator}},
		{"space in name", crlf("Bad Name: x\n\n"), []DefectKind{DefectMalformedHeaderLine, DefectNoBodySeparator}},
		{"empty name", crlf(": value\n\n"), []DefectKind{DefectMalformedHeaderLine, DefectNoBodySeparator}},
		{"long line", crlf("Subject: " + strings.Repeat("x", 1000) + "\n\n"), []DefectKind{DefectLongLine}},
		{"nul byte", crlf("Subject: a\x00b\n\n"), []DefectKind{DefectNULByte}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseBytes([]byte(tt.raw), Options{HeadersOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if got := defectKinds(m); !slices.Equal(got, tt.want) {
				t.Errorf("defects = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMalformedHeaderKeepsPrecedingFields(t *testing.T) {
	m, _ := ParseBytes([]byte(crlf("From: a@example.com\nSubject: s\ngarbage line\nTo: hidden@example.com\n")), Options{})
	if len(m.Headers) != 2 {
		t.Errorf("headers = %d", len(m.Headers))
	}
	if !strings.HasPrefix(string(m.Body), "garbage line") {
		t.Errorf("body = %q", m.Body)
	}
}

func TestParseHeadersOnlyInput(t *testing.T) {
	m, _ := ParseBytes([]byte(crlf("From: a@example.com\nTo: b@example.com")), Options{HeadersOnly: true})
	if len(m.Headers) != 2 || m.HasBody {
		t.Errorf("headers = %d, hasBody = %v", len(m.Headers), m.HasBody)
	}
	if v, _ := m.First("To"); v != "b@example.com" {
		t.Errorf("To = %q", v)
	}
}

func TestParseAddressList(t *testing.T) {
	list, err := ParseAddressList(`"Alice A." <Alice@Example.COM>, bob@sub.example.net`)
	if err != nil || len(list) != 2 || list[0].Domain != "example.com" || list[1].Domain != "sub.example.net" || list[0].Name != "Alice A." {
		t.Errorf("list = %+v, %v", list, err)
	}
	if _, err := ParseAddressList("not an address"); err == nil {
		t.Error("expected error")
	}
}

func TestParseReturnPath(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"<bounce@example.com>", "bounce@example.com", false},
		{" bounce@example.com ", "bounce@example.com", false},
		{"<>", "", true},
		{"<nobody>", "", true},
	}
	for _, tt := range tests {
		got, err := ParseReturnPath(tt.in)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("ParseReturnPath(%q) = %q, %v", tt.in, got, err)
		}
	}
	if _, err := ParseReturnPath("<>"); err != ErrNullReversePath {
		t.Errorf("null path err = %v", err)
	}
}

func TestDomainOf(t *testing.T) {
	for in, want := range map[string]string{
		"a@Example.COM":   "example.com",
		"a@b@example.org": "example.org",
		"noat":            "",
		"a@example.com.":  "example.com",
	} {
		if got := DomainOf(in); got != want {
			t.Errorf("DomainOf(%q) = %q", in, got)
		}
	}
}
