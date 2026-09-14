//go:build smoke

// Package smoke checks a release binary end to end. It is excluded from
// normal test runs; run it against a built artifact:
//
//	MAILAUTHPROBE_BIN=dist/mailauthprobe go test -tags smoke ./test/smoke
//
// MAILAUTHPROBE_EXPECT_VERSION, when set, must match the reported version.
package smoke

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
)

var root = filepath.Join("..", "..")

func binary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("MAILAUTHPROBE_BIN")
	if bin == "" {
		t.Fatal("MAILAUTHPROBE_BIN must point at the binary under test")
	}
	// Relative paths are resolved against the repository root, where the
	// command is normally invoked, not against this package directory.
	if !filepath.IsAbs(bin) {
		bin = filepath.Join(root, bin)
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatal(err)
	}
	return abs
}

func localResolver(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "testdata", "dns", "zone.txt"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnstest.NewServer(dnstest.MustParseZone(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv.Addr()
}

func runBinary(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return out.String(), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), 0
}

func decode(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc["schema_version"] != "1" {
		t.Errorf("schema_version = %v", doc["schema_version"])
	}
	return doc
}

func TestHelp(t *testing.T) {
	out, code := runBinary(t, "--help")
	if code != 0 || !strings.Contains(out, "Exit codes:") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestVersion(t *testing.T) {
	out, code := runBinary(t, "version", "--json")
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	var v struct {
		Version, Commit, GoVersion, Platform string
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v.Version == "" || v.Version == "devel" || v.Platform == "" {
		t.Errorf("release binary lacks version metadata: %+v", v)
	}
	if want := os.Getenv("MAILAUTHPROBE_EXPECT_VERSION"); want != "" && v.Version != want {
		t.Errorf("version = %q, want %q", v.Version, want)
	}
	if text, _ := runBinary(t, "version"); !strings.HasPrefix(text, "mailauthprobe ") {
		t.Errorf("text version output: %s", text)
	}
}

func TestDomain(t *testing.T) {
	out, code := runBinary(t, "domain", "test.example", "--resolver", localResolver(t), "--dkim-selector", "s2026", "--json")
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	doc := decode(t, out)
	if doc["kind"] != "domain" || doc["target"] != "test.example" {
		t.Errorf("kind/target = %v/%v", doc["kind"], doc["target"])
	}
	if hs := doc["summary"].(map[string]any)["highest_severity"]; hs != "low" {
		t.Errorf("highest_severity = %v", hs)
	}
}

func TestValidMessage(t *testing.T) {
	out, code := runBinary(t, "message", filepath.Join("testdata", "messages", "valid.eml"), "--resolver", localResolver(t), "--json")
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	msg := decode(t, out)["message"].(map[string]any)
	if msg["dmarc"].(map[string]any)["result"] != "pass" || msg["spf"].(map[string]any)["result"] != "pass" {
		t.Errorf("unexpected verdicts: dmarc=%v spf=%v", msg["dmarc"], msg["spf"])
	}
	dkim := msg["dkim"].([]any)
	if len(dkim) != 1 || dkim[0].(map[string]any)["result"] != "pass" {
		t.Errorf("dkim = %v", dkim)
	}

	text, code := runBinary(t, "message", filepath.Join("testdata", "messages", "valid.eml"), "--resolver", localResolver(t))
	if code != 0 || !strings.Contains(text, "DMARC:             pass") {
		t.Errorf("text output (code %d):\n%s", code, text)
	}
}

func TestMalformedMessage(t *testing.T) {
	out, code := runBinary(t, "message", filepath.Join("testdata", "messages", "malformed.eml"), "--resolver", localResolver(t), "--json")
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	found := false
	for _, f := range decode(t, out)["findings"].([]any) {
		if f.(map[string]any)["id"] == "MAIL-MSG-002" {
			found = true
		}
	}
	if !found {
		t.Error("malformed MIME finding missing")
	}
}

func TestOversizedInputExitCode(t *testing.T) {
	_, code := runBinary(t, "message", filepath.Join("testdata", "messages", "oversized-headers.eml"), "--resolver", localResolver(t), "-q")
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
}
