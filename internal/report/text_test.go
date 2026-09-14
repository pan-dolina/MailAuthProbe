package report_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/analyzer"
	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/marcindolinski/mailauthprobe/internal/report"
)

func zone(t *testing.T) *dnstest.Zone {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dns", "zone.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return dnstest.MustParseZone(string(b))
}

func messageReport(t *testing.T, name string) *report.Report {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "testdata", "messages", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := analyzer.Message(context.Background(), f, name, false, analyzer.Options{Resolver: zone(t), Now: time.Unix(1789380000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func render(t *testing.T, rep *report.Report, opts report.TextOptions) string {
	t.Helper()
	var buf bytes.Buffer
	if err := report.WriteText(&buf, rep, opts); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestTextDomain(t *testing.T) {
	rep := analyzer.Domain(context.Background(), "test.example", analyzer.Options{Resolver: zone(t), DKIMSelectors: []string{"s2026"}})
	out := render(t, rep, report.TextOptions{})
	for _, want := range []string{
		"MailAuthProbe domain: test.example",
		"mx1.test.example",
		"v=spf1 ip4:192.0.2.0/24",
		"DNS lookups: 0/10",
		"policy reject",
		"s2026._domainkey.test.example: RSA 2048 bits",
		"MAIL-MTASTS-001",
		"passing check(s) hidden",
		"DNS queries",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour codes emitted with Color=false")
	}
	if strings.Contains(out, "MAIL-SPF-022") {
		t.Error("pass findings shown without --verbose")
	}

	verbose := render(t, rep, report.TextOptions{Verbose: true, Color: true})
	if !strings.Contains(verbose, "MAIL-SPF-022") || !strings.Contains(verbose, "\x1b[") || !strings.Contains(verbose, "https://www.rfc-editor.org/") {
		t.Errorf("verbose output incomplete:\n%s", verbose)
	}
}

func TestTextMessage(t *testing.T) {
	out := render(t, messageReport(t, "valid.eml"), report.TextOptions{Verbose: true})
	for _, want := range []string{
		"From:              Alice <alice@test.example>",
		"SPF:               pass (test.example) inputs inferred",
		"DKIM:              pass (1 of 1 signatures valid)",
		"DMARC:             pass (test.example, policy reject)",
		"#1  mail.test.example [192.0.2.10] → mx.receiver.example",
		"TLS (inferred)",
		"#1 pass d=test.example s=s2026 rsa-sha256 relaxed/relaxed",
		"client IP:         192.0.2.10 (received, inferred)",
		"#1 mx.receiver.example: dkim=pass spf=pass dmarc=pass",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

func TestTextSPFTree(t *testing.T) {
	z := dnstest.MustParseZone(`
tree.example.     TXT "v=spf1 include:a.tree.example include:b.tree.example -all"
a.tree.example.   TXT "v=spf1 include:c.tree.example -all"
b.tree.example.   TXT "v=spf1 ip4:192.0.2.1 -all"
c.tree.example.   TXT "v=spf1 ip4:192.0.2.2 -all"
`)
	rep := analyzer.Domain(context.Background(), "tree.example", analyzer.Options{Resolver: z})
	out := render(t, rep, report.TextOptions{})
	want := "" +
		"  tree.example (2 lookup(s), 3 with includes)\n" +
		"  ├─ include:a.tree.example (1 lookup(s))\n" +
		"  │  └─ include:c.tree.example (0 lookup(s))\n" +
		"  └─ include:b.tree.example (0 lookup(s))\n"
	if !strings.Contains(out, want) {
		t.Errorf("tree not rendered as expected:\n%s", out)
	}
}
