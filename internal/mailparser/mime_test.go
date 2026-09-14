package mailparser

import (
	"slices"
	"testing"
)

func TestParseMIMEStructure(t *testing.T) {
	raw := crlf(`From: a@example.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

preamble
--outer
Content-Type: multipart/alternative; boundary=inner

--inner
Content-Type: text/plain; charset=utf-8

plain
--inner
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<p>html</p>
--inner--
--outer
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQK
--outer--
epilogue
`)
	m, err := ParseBytes([]byte(raw), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Defects) != 0 {
		t.Errorf("defects = %v", m.Defects)
	}
	root := m.MIME
	if root.ContentType != "multipart/mixed" || root.Boundary != "outer" || len(root.Parts) != 2 {
		t.Fatalf("root = %+v", root)
	}
	alt := root.Parts[0]
	if alt.ContentType != "multipart/alternative" || len(alt.Parts) != 2 || alt.Parts[1].TransferEncoding != "quoted-printable" || alt.Parts[1].Depth != 2 {
		t.Errorf("alternative = %+v", alt)
	}
	att := root.Attachments()
	if len(att) != 1 || att[0].Filename != "invoice.pdf" || att[0].Disposition != "attachment" {
		t.Errorf("attachments = %+v", att)
	}
}

func TestParseMIMEDefaults(t *testing.T) {
	m, _ := ParseBytes([]byte(crlf("From: a@example.com\n\nhello\n")), Options{})
	if m.MIME == nil || m.MIME.ContentType != "text/plain" || m.MIME.Charset != "us-ascii" {
		t.Errorf("mime = %+v", m.MIME)
	}
}

func TestParseMIMEDefects(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []DefectKind
	}{
		{"missing boundary", "MIME-Version: 1.0\nContent-Type: multipart/mixed\n\nbody\n", []DefectKind{DefectMIMEMissingBoundary}},
		{"boundary absent from body", "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=zzz\n\nbody\n", []DefectKind{DefectMIMENoParts}},
		{"unterminated", "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\ntext without end\n",
			[]DefectKind{DefectMIMEUnterminated}},
		{"invalid content type", "Content-Type: text/\n\nbody\n", []DefectKind{DefectMIMEInvalidContentType}},
		{"bad transfer encoding", "Content-Type: text/plain\nContent-Transfer-Encoding: x-uuencode\n\nbody\n", []DefectKind{DefectMIMEBadEncoding}},
		{"missing version", "Content-Type: multipart/mixed; boundary=b\n\n--b\n\nx\n--b--\n", []DefectKind{DefectMIMEMissingVersion}},
		{"only closing boundary", "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b--\n", []DefectKind{DefectMIMENoParts}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseBytes([]byte(crlf(tt.raw)), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := defectKinds(m); !slices.Equal(got, tt.want) {
				t.Errorf("defects = %v, want %v", got, tt.want)
			}
		})
	}
}
