package mailparser

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// endlessReader yields an unbounded stream of header lines.
type endlessReader struct{ read int64 }

func (r *endlessReader) Read(p []byte) (int, error) {
	line := []byte("X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
	n := 0
	for n < len(p) {
		n += copy(p[n:], line)
	}
	r.read += int64(n)
	return n, nil
}

func TestParseStopsReadingAtMessageLimit(t *testing.T) {
	r := &endlessReader{}
	_, err := Parse(r, Options{Limits: Limits{MaxMessageBytes: 1 << 20}})
	var le *LimitError
	if !errors.As(err, &le) || le.Limit != "message size" {
		t.Fatalf("err = %v", err)
	}
	if r.read > 2<<20 {
		t.Errorf("read %d bytes from an endless stream", r.read)
	}
}

func TestParseLimits(t *testing.T) {
	manyHeaders := strings.Repeat("X-A: b\r\n", 50) + "\r\nbody"
	bigHeader := "Subject: " + strings.Repeat("x", 5000) + "\r\n\r\nbody"
	tests := []struct {
		name   string
		raw    string
		limits Limits
		limit  string
	}{
		{"message size", strings.Repeat("a", 2000), Limits{MaxMessageBytes: 1000}, "message size"},
		{"header count", manyHeaders, Limits{MaxHeaders: 49}, "header field count"},
		{"header bytes", bigHeader, Limits{MaxHeaderBytes: 4096}, "header section size"},
		{"header bytes without separator", "Subject: " + strings.Repeat("x", 5000), Limits{MaxHeaderBytes: 4096}, "header section size"},
		{"many small lines", strings.Repeat("X-A: b\r\n", 1000), Limits{MaxHeaderBytes: 1024, MaxHeaders: 10000}, "header section size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.raw), Options{Limits: tt.limits})
			var le *LimitError
			if !errors.As(err, &le) || le.Limit != tt.limit {
				t.Fatalf("err = %v, want %s limit", err, tt.limit)
			}
		})
	}

	// Exactly at the limits is accepted.
	if _, err := Parse(strings.NewReader(manyHeaders), Options{Limits: Limits{MaxHeaders: 50}}); err != nil {
		t.Errorf("50 headers with limit 50: %v", err)
	}
}

func nestedMultipart(depth int) string {
	var b strings.Builder
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "--b%d\r\nContent-Type: multipart/mixed; boundary=b%d\r\n\r\n", i, i+1)
	}
	fmt.Fprintf(&b, "--b%d\r\nContent-Type: text/plain\r\n\r\nleaf\r\n--b%d--\r\n", depth, depth)
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--b%d--\r\n", i)
	}
	return b.String()
}

func TestMIMEDepthLimit(t *testing.T) {
	m, err := Parse(strings.NewReader(nestedMultipart(30)), Options{Limits: Limits{MaxMIMEDepth: 10}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(defectKinds(m), DefectMIMEDepthExceeded) {
		t.Errorf("defects = %v", m.Defects)
	}
	depth := 0
	for p := m.MIME; len(p.Parts) > 0; p = p.Parts[0] {
		depth++
	}
	if depth > 10 {
		t.Errorf("walked %d levels", depth)
	}

	m, _ = Parse(strings.NewReader(nestedMultipart(5)), Options{Limits: Limits{MaxMIMEDepth: 10}})
	if len(m.Defects) != 0 {
		t.Errorf("shallow nesting produced defects: %v", m.Defects)
	}
}

func TestMIMEPartsLimit(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n")
	for range 1000 {
		b.WriteString("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n")
	}
	b.WriteString("--b--\r\n")
	m, err := Parse(io.NopCloser(&b), Options{Limits: Limits{MaxMIMEParts: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(defectKinds(m), DefectMIMEPartsExceeded) || len(m.MIME.Parts) >= 100 {
		t.Errorf("parts = %d, defects = %v", len(m.MIME.Parts), m.Defects)
	}
}

func TestMIMENestedCopiesAreBounded(t *testing.T) {
	var b strings.Builder
	depth := 20
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "--b%d\r\nContent-Type: multipart/mixed; boundary=b%d\r\n\r\n", i, i+1)
	}
	fmt.Fprintf(&b, "--b%d\r\nContent-Type: text/plain\r\n\r\n%s\r\n--b%d--\r\n", depth, strings.Repeat("x", 4<<20), depth)
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--b%d--\r\n", i)
	}
	data := []byte(b.String())

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	m, err := ParseBytes(data, Options{Limits: Limits{MaxMIMEDepth: 30}})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(defectKinds(m), DefectMIMESizeExceeded) {
		t.Errorf("defects = %v", m.Defects)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(6*len(data)) {
		t.Errorf("allocated %d bytes for a %d byte message", alloc, len(data))
	}
}
