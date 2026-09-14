package analyzer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
	"github.com/marcindolinski/mailauthprobe/internal/report"
)

func testdata(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func fixtureZone(t *testing.T) *dnstest.Zone {
	t.Helper()
	b, err := os.ReadFile(testdata(t, "dns", "zone.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return dnstest.MustParseZone(string(b))
}

func ids(r *report.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.ID)
	}
	return out
}

var fixedNow = time.Unix(1789380000, 0)

func TestDomainFixture(t *testing.T) {
	rep := Domain(context.Background(), "test.example", Options{Resolver: fixtureZone(t), DKIMSelectors: []string{"s2026"}, Now: fixedNow})
	got := ids(rep)
	for _, want := range []string{"MAIL-MX-015", "MAIL-SPF-022", "MAIL-DMARC-017", "MAIL-DKIM-012", "MAIL-MTASTS-001", "MAIL-TLSRPT-001"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(rep.Errors) != 0 {
		t.Errorf("errors = %+v", rep.Errors)
	}
	if rep.Summary.DNSQueries == 0 || rep.Summary.HighestSeverity != "low" {
		t.Errorf("summary = %+v", rep.Summary)
	}
	if !slices.IsSortedFunc(rep.Findings, findings.Compare) {
		t.Error("findings are not sorted")
	}
}

func TestDomainDNSFailure(t *testing.T) {
	zone := dnstest.MustParseZone("down.example. TIMEOUT\n_dmarc.down.example. TIMEOUT\n")
	rep := Domain(context.Background(), "down.example", Options{Resolver: zone})
	if !rep.HasErrorKind(report.ErrorDNS) {
		t.Errorf("errors = %+v", rep.Errors)
	}
}

func TestDomainQueryBudget(t *testing.T) {
	rep := Domain(context.Background(), "test.example", Options{Resolver: fixtureZone(t), QueryBudget: 3})
	if !slices.Contains(ids(rep), findings.DNSQueryBudgetExceeded.ID) {
		t.Errorf("findings = %v", ids(rep))
	}
	if rep.Summary.DNSQueries <= 3 {
		t.Errorf("dns queries = %d", rep.Summary.DNSQueries)
	}
}

func analyzeFile(t *testing.T, name string, headersOnly bool, opts Options) *report.Report {
	t.Helper()
	f, err := os.Open(testdata(t, "messages", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if opts.Resolver == nil {
		opts.Resolver = fixtureZone(t)
	}
	opts.Now = fixedNow
	rep, err := Message(context.Background(), f, name, headersOnly, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestMessageValid(t *testing.T) {
	rep := analyzeFile(t, "valid.eml", false, Options{})
	m := rep.Message
	if m.SPF.Result != "pass" || m.DMARC.Result != "pass" || len(m.DKIM) != 1 || m.DKIM[0].Result != "pass" {
		t.Fatalf("spf=%s dmarc=%s dkim=%+v", m.SPF.Result, m.DMARC.Result, m.DKIM)
	}
	if !m.SPF.Inputs.IP.Inferred || m.SPF.Inputs.IP.Value != "192.0.2.10" || m.SPF.Inputs.MailFrom.Source != "return-path" {
		t.Errorf("inputs = %+v", m.SPF.Inputs)
	}
	got := ids(rep)
	for _, want := range []string{"MAIL-DKIM-020", "MAIL-SPF-030", "MAIL-DMARC-030", "MAIL-AR-003", "MAIL-SPF-035"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if rep.Summary.HighestSeverity != "info" {
		t.Errorf("highest severity = %s: %v", rep.Summary.HighestSeverity, got)
	}
}

func TestMessageFlagsOverrideInference(t *testing.T) {
	rep := analyzeFile(t, "valid.eml", false, Options{SourceIP: "203.0.113.66", HELO: "evil.example", MailFrom: "x@test.example"})
	m := rep.Message
	if m.SPF.Result != "fail" || m.SPF.Inputs.IP.Inferred || m.DMARC.Result != "pass" {
		t.Errorf("spf=%s inputs=%+v dmarc=%s", m.SPF.Result, m.SPF.Inputs, m.DMARC.Result)
	}
	if !slices.Contains(ids(rep), "MAIL-AR-002") {
		t.Errorf("expected AR mismatch: %v", ids(rep))
	}
}

func TestMessageHeadersOnly(t *testing.T) {
	rep := analyzeFile(t, "dkim-body-hash-mismatch.eml", true, Options{})
	if rep.Kind != report.KindHeaders || rep.Message.BodyAvailable {
		t.Fatalf("kind = %s", rep.Kind)
	}
	got := ids(rep)
	if !slices.Contains(got, "MAIL-DKIM-031") || !slices.Contains(got, "MAIL-MSG-014") {
		t.Errorf("findings = %v", got)
	}
}

func TestMessageInputErrors(t *testing.T) {
	_, err := Message(context.Background(), strings.NewReader(""), "-", false, Options{Resolver: dnstest.NewZone()})
	var ie *InputError
	if !errors.As(err, &ie) {
		t.Errorf("empty input err = %v", err)
	}
	big := strings.NewReader("Subject: " + strings.Repeat("x", 2048) + "\r\n\r\n")
	rep, err := Message(context.Background(), big, "-", false, Options{Resolver: dnstest.NewZone(), Limits: mailparser.Limits{MaxHeaderBytes: 1024}})
	if !errors.As(err, &ie) || !rep.HasErrorKind(report.ErrorInput) {
		t.Errorf("oversized err = %v, errors = %+v", err, rep.Errors)
	}
}

func TestMessageStructureFindings(t *testing.T) {
	raw := "From: Alice <alice@test.example>\r\n" +
		"From: Mallory <m@evil.example>\r\n" +
		"Reply-To: collect@evil.example\r\n" +
		"Subject: Invoice\r\n" +
		"Date: yesterday\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n" +
		"\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--b\r\nContent-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nMZ\r\n--b--\r\n"
	rep, err := Message(context.Background(), strings.NewReader(raw), "-", false, Options{Resolver: fixtureZone(t), Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(rep)
	for _, want := range []string{"MAIL-MSG-005", "MAIL-MSG-006", "MAIL-MSG-010", "MAIL-MSG-012", "MAIL-DMARC-033", "MAIL-DKIM-025", "MAIL-RCVD-001", "MAIL-SPF-036"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}
