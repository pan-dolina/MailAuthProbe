package dkim_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dkim"
	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
)

func BenchmarkVerifyFixture(b *testing.B) {
	root := filepath.Join("..", "..", "testdata")
	zoneText, _ := os.ReadFile(filepath.Join(root, "dns", "zone.txt"))
	zone := dnstest.MustParseZone(string(zoneText))
	raw, err := os.ReadFile(filepath.Join(root, "messages", "dkim-multiple.eml"))
	if err != nil {
		b.Fatal(err)
	}
	msg, err := mailparser.ParseBytes(raw, mailparser.Options{})
	if err != nil {
		b.Fatal(err)
	}
	now := time.Unix(1789380000, 0)
	for b.Loop() {
		vs := dkim.VerifyMessage(context.Background(), zone, msg, dkim.VerifyOptions{Now: now})
		if len(vs) != 3 {
			b.Fatal("unexpected verification count")
		}
	}
}

func BenchmarkCanonicalBodyRelaxed(b *testing.B) {
	body := make([]byte, 0, 1<<20)
	for len(body) < 1<<20 {
		body = append(body, "Lorem ipsum  dolor sit amet,\t consectetur adipiscing elit.   \r\n"...)
	}
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		dkim.CanonicalBody(discard{}, body, dkim.CanonRelaxed, -1)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
