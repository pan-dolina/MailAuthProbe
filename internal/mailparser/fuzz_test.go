package mailparser

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func addMessageSeeds(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "messages", "*"))
	for _, name := range files {
		if data, err := os.ReadFile(name); err == nil && len(data) < 64<<10 {
			f.Add(data)
		}
	}
	f.Add([]byte("From: a@example.com\r\n\r\n"))
	f.Add([]byte(" \r\n:\r\n\r\n"))
	f.Add([]byte("Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\n--\r\n"))
}

// FuzzParseHeaders checks that header parsing never panics and that the raw
// bytes of the parsed fields are taken from the header section in order.
func FuzzParseHeaders(f *testing.F) {
	addMessageSeeds(f)
	limits := Limits{MaxMessageBytes: 1 << 20, MaxHeaderBytes: 64 << 10, MaxHeaders: 200, MaxMIMEDepth: 8, MaxMIMEParts: 64}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseBytes(data, Options{HeadersOnly: true, Limits: limits})
		if err != nil {
			return
		}
		// Raw field bytes must appear in the header section, in order and
		// without overlapping; skipped lines may lie between them.
		off := 0
		for _, h := range m.Headers {
			if len(h.Raw) == 0 {
				t.Fatalf("header %q has no raw bytes", h.Name)
			}
			i := bytes.Index(data[off:], h.Raw)
			if i < 0 || off+i+len(h.Raw) > m.HeaderSize {
				t.Fatalf("raw bytes of %q not found in order within the header section", h.Name)
			}
			off += i + len(h.Raw)
		}
		if m.HeaderSize > len(data) || (m.HasBody && m.HeaderSize+len(m.Body) != len(data)) {
			t.Fatalf("inconsistent sizes: header %d body %d input %d", m.HeaderSize, len(m.Body), len(data))
		}
	})
}

// FuzzParseMIME exercises the MIME walker with its limits.
func FuzzParseMIME(f *testing.F) {
	addMessageSeeds(f)
	f.Add([]byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\n\r\nx\r\n--a--\r\n--a--\r\n"))
	limits := Limits{MaxMessageBytes: 1 << 20, MaxHeaderBytes: 64 << 10, MaxHeaders: 200, MaxMIMEDepth: 8, MaxMIMEParts: 64}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseBytes(data, Options{Limits: limits})
		if err != nil {
			return
		}
		if m.MIME == nil {
			t.Fatal("full parse produced no MIME tree")
		}
		count := 0
		var walk func(p *Part)
		walk = func(p *Part) {
			count++
			if p.Depth > limits.MaxMIMEDepth {
				t.Fatalf("part depth %d exceeds limit", p.Depth)
			}
			for _, c := range p.Parts {
				walk(c)
			}
		}
		walk(m.MIME)
		if count > limits.MaxMIMEParts+1 {
			t.Fatalf("%d parts exceed limit %d", count, limits.MaxMIMEParts)
		}
		_ = m.MIME.Attachments()
		for _, h := range m.Get("From") {
			_, _ = ParseAddressList(h.Value)
		}
		for _, h := range m.Get("Return-Path") {
			_, _ = ParseReturnPath(h.Value)
		}
	})
}
