package mailparser

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkParseFixture(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "messages", "dkim-multiple.eml"))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, err := ParseBytes(data, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseLargeMultipart(b *testing.B) {
	var buf bytes.Buffer
	buf.WriteString("From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n")
	for i := range 200 {
		fmt.Fprintf(&buf, "--b\r\nContent-Type: application/octet-stream; name=\"f%d.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n", i)
		for range 40 {
			buf.WriteString("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAx\r\n")
		}
	}
	buf.WriteString("--b--\r\n")
	data := buf.Bytes()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, err := ParseBytes(data, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}
