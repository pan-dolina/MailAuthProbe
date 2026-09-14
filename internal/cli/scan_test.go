package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
)

func fixtureServer(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dns", "zone.txt"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnstest.NewServer(dnstest.MustParseZone(string(b)))
	if err != nil {
		t.Skip("cannot start DNS server:", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv.Addr()
}

func messagePath(name string) string {
	return filepath.Join("..", "..", "testdata", "messages", name)
}

func TestScanCommands(t *testing.T) {
	dns := fixtureServer(t)
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"domain text", []string{"domain", "test.example", "--resolver", dns, "--no-color"}, ExitOK, "MAIL-MTASTS-001"},
		{"domain fail-on low", []string{"domain", "test.example", "--resolver", dns, "--fail-on", "low", "-q"}, ExitFindings, ""},
		{"domain fail-on medium", []string{"domain", "test.example", "--resolver", dns, "--fail-on", "medium", "-q"}, ExitOK, ""},
		{"domain selector", []string{"domain", "test.example", "--resolver", dns, "--dkim-selector", "s2026,ed2026"}, ExitOK, "ed2026._domainkey.test.example: ED25519 256 bits"},
		{"domain invalid", []string{"domain", "localhost"}, ExitUsage, "not a fully qualified domain name"},
		{"domain ip", []string{"domain", "192.0.2.1"}, ExitUsage, "not a fully qualified domain name"},
		{"domain missing arg", []string{"domain"}, ExitUsage, "expects a domain name"},
		{"domain bad selector", []string{"domain", "test.example", "--dkim-selector", "a b"}, ExitUsage, "invalid DKIM selector"},
		{"bad resolver", []string{"domain", "test.example", "--resolver", "dns.example"}, ExitUsage, "invalid --resolver"},
		{"dns unreachable", []string{"domain", "test.example", "--resolver", "127.0.0.1:1", "--timeout", "2s"}, ExitNetwork, "error"},
		{"message", []string{"message", messagePath("valid.eml"), "--resolver", dns}, ExitOK, "DMARC:             pass"},
		{"message fail-on high", []string{"message", messagePath("dkim-signature-mismatch.eml"), "--resolver", dns, "--fail-on", "high"}, ExitFindings, "MAIL-DKIM-021"},
		{"message flags", []string{"message", messagePath("valid.eml"), "--resolver", dns, "--source-ip", "203.0.113.66", "--mail-from", "<>", "--helo", "evil.example"}, ExitOK, "null sender"},
		{"message bad ip", []string{"message", messagePath("valid.eml"), "--source-ip", "999.1.1.1"}, ExitUsage, "invalid --source-ip"},
		{"message bad mail-from", []string{"message", messagePath("valid.eml"), "--mail-from", "nobody"}, ExitUsage, "invalid --mail-from"},
		{"message missing file", []string{"message", "does-not-exist.eml"}, ExitInput, "cannot open message"},
		{"message directory", []string{"message", "."}, ExitInput, "is a directory"},
		{"headers", []string{"headers", messagePath("dkim-body-hash-mismatch.eml"), "--resolver", dns}, ExitOK, "MAIL-MSG-014"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := run(t, tt.args...)
			if code != tt.code {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.code, stdout, stderr)
			}
			if tt.want != "" && !strings.Contains(stdout+stderr, tt.want) {
				t.Errorf("output lacks %q\nstdout:\n%s\nstderr:\n%s", tt.want, stdout, stderr)
			}
			if slices.Contains(tt.args, "-q") && stdout != "" {
				t.Errorf("quiet mode wrote output: %s", stdout)
			}
		})
	}
}

func TestMessageFromStdinJSON(t *testing.T) {
	dns := fixtureServer(t)
	raw, err := os.ReadFile(messagePath("valid.eml"))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	app := &App{Stdin: strings.NewReader(string(raw)), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }}
	if code := app.Execute(t.Context(), []string{"message", "-", "--resolver", dns, "--json"}); code != ExitOK {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Target        string `json:"target"`
		Message       struct {
			DMARC struct {
				Result string `json:"result"`
			} `json:"dmarc"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != "1" || doc.Target != "-" || doc.Message.DMARC.Result != "pass" {
		t.Errorf("doc = %+v", doc)
	}
}

func TestInputErrorJSONStillWritten(t *testing.T) {
	var out, errb strings.Builder
	app := &App{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }}
	code := app.Execute(t.Context(), []string{"message", "-", "--json", "--resolver", "127.0.0.1:1"})
	if code != ExitInput || !strings.Contains(out.String(), `"kind": "input"`) {
		t.Errorf("code = %d, stdout = %s", code, out.String())
	}
}

func TestNoColorEnvironment(t *testing.T) {
	app := &App{Stdout: os.Stdout, Getenv: func(k string) string {
		if k == "NO_COLOR" {
			return "1"
		}
		return ""
	}}
	if app.useColor() {
		t.Error("NO_COLOR ignored")
	}
}

func TestStalledStdinHonoursTimeout(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	var out, errb strings.Builder
	app := &App{Stdin: pr, Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }}
	done := make(chan int, 1)
	go func() {
		done <- app.Execute(t.Context(), []string{"message", "-", "--timeout", "200ms", "--resolver", "127.0.0.1:1"})
	}()
	select {
	case code := <-done:
		if code != ExitInput || !strings.Contains(errb.String(), "deadline exceeded") {
			t.Errorf("code = %d, stderr = %s", code, errb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled standard input ignored --timeout")
	}
}
