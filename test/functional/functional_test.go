// Package functional runs the compiled mailauthprobe binary against the
// fixtures in testdata, using a local DNS server. No test needs Internet
// access.
package functional

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/golden")

var (
	binary   string
	resolver string
	root     = filepath.Join("..", "..")
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "mailauthprobe-functional-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	binary = filepath.Join(dir, "mailauthprobe")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-trimpath",
		"-ldflags", "-X github.com/pan-dolina/mailauthprobe/internal/version.Version=v0.0.0-functional",
		"-o", binary, "./cmd/mailauthprobe")
	build.Dir = root
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building mailauthprobe:", err)
		return 1
	}

	zoneText, err := os.ReadFile(filepath.Join(root, "testdata", "dns", "zone.txt"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	srv, err := dnstest.NewServer(dnstest.MustParseZone(string(zoneText)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "starting DNS server:", err)
		return 1
	}
	defer srv.Close()
	resolver = srv.Addr()
	return m.Run()
}

type result struct {
	stdout, stderr string
	code           int
}

func mailauthprobe(t *testing.T, stdin []byte, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running mailauthprobe: %v", err)
	}
	return result{out.String(), errb.String(), code}
}

type jsonReport struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	Summary       struct {
		HighestSeverity string `json:"highest_severity"`
	} `json:"summary"`
	Message *struct {
		SPF struct {
			Result string `json:"result"`
		} `json:"spf"`
		DMARC struct {
			Result      string `json:"result"`
			Disposition string `json:"disposition"`
		} `json:"dmarc"`
		DKIM []struct {
			Result  string `json:"result"`
			Failure string `json:"failure"`
		} `json:"dkim"`
	} `json:"message"`
	Findings []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	} `json:"findings"`
	Errors []struct {
		Kind string `json:"kind"`
	} `json:"errors"`
}

func parseReport(t *testing.T, out string) jsonReport {
	t.Helper()
	var r jsonReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if r.SchemaVersion != "1" {
		t.Errorf("schema_version = %q", r.SchemaVersion)
	}
	return r
}

func (r jsonReport) ids() []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.ID)
	}
	return out
}

// fixture returns a slash-separated path so that the target echoed in reports
// matches the golden files on every platform.
func fixture(name string) string { return "testdata/messages/" + name }

func TestMessageFixtures(t *testing.T) {
	tests := []struct {
		file      string
		command   string
		args      []string
		code      int
		spf       string
		dmarc     string
		dkim      []string
		want      []string
		forbidden []string
	}{
		{file: "valid.eml", spf: "pass", dmarc: "pass", dkim: []string{"pass"},
			want: []string{"MAIL-DKIM-020", "MAIL-SPF-030", "MAIL-DMARC-030", "MAIL-AR-003"}, forbidden: []string{"MAIL-AR-002"}},
		{file: "dkim-signature-mismatch.eml", spf: "pass", dmarc: "pass", dkim: []string{"fail"}, want: []string{"MAIL-DKIM-021"}},
		{file: "dkim-body-hash-mismatch.eml", spf: "pass", dmarc: "pass", dkim: []string{"fail"}, want: []string{"MAIL-DKIM-022"}},
		{file: "dkim-multiple.eml", spf: "pass", dmarc: "pass", dkim: []string{"permerror", "pass", "pass"}, want: []string{"MAIL-DKIM-023", "MAIL-DKIM-020", "MAIL-DKIM-011"}},
		{file: "spf-pass.eml", spf: "pass", dmarc: "pass", want: []string{"MAIL-SPF-030", "MAIL-DKIM-025"}},
		{file: "spf-fail.eml", spf: "fail", dmarc: "fail", want: []string{"MAIL-SPF-031", "MAIL-DMARC-031"}},
		{file: "spf-lookup-limit.eml", spf: "permerror", dmarc: "fail", want: []string{"MAIL-SPF-034"}},
		{file: "spf-loop.eml", spf: "permerror", dmarc: "fail", want: []string{"MAIL-SPF-034"}},
		{file: "dmarc-reject.eml", spf: "pass", dmarc: "fail", dkim: []string{"pass"}, want: []string{"MAIL-DMARC-031", "MAIL-DMARC-036", "MAIL-DMARC-037"}},
		{file: "dmarc-none.eml", spf: "pass", dmarc: "fail", want: []string{"MAIL-DMARC-031"}},
		{file: "dmarc-strict-alignment-fail.eml", spf: "pass", dmarc: "fail", dkim: []string{"pass"}, want: []string{"MAIL-DMARC-035"}},
		{file: "dmarc-relaxed-alignment-pass.eml", spf: "fail", dmarc: "pass", dkim: []string{"pass"}, want: []string{"MAIL-DMARC-030"}},
		{file: "malformed.eml", dmarc: "indeterminate", want: []string{"MAIL-MSG-002", "MAIL-MSG-010", "MAIL-SPF-036", "MAIL-DMARC-038"}},
		{file: "malformed-headers.eml", dmarc: "permerror", want: []string{"MAIL-MSG-001", "MAIL-MSG-006", "MAIL-DMARC-033"}},
		{file: "conflicting-auth-results.eml", spf: "pass", dmarc: "pass", dkim: []string{"fail"}, want: []string{"MAIL-AR-001", "MAIL-AR-002"}},
		{file: "no-dkim.eml", spf: "pass", dmarc: "pass", want: []string{"MAIL-DKIM-025"}},
		{file: "headers.txt", command: "headers", spf: "pass", dmarc: "pass", dkim: []string{"neutral"}, want: []string{"MAIL-DKIM-031", "MAIL-MSG-014"}},
		{file: "valid.eml", args: []string{"--source-ip", "203.0.113.66"}, spf: "fail", dmarc: "pass", dkim: []string{"pass"}, want: []string{"MAIL-SPF-031", "MAIL-SPF-035", "MAIL-AR-002"}},
		{file: "spf-fail.eml", args: []string{"--fail-on", "high"}, code: 1, spf: "fail", dmarc: "fail"},
		{file: "valid.eml", args: []string{"--fail-on", "low"}, code: 0, spf: "pass", dmarc: "pass", dkim: []string{"pass"}},
	}
	for _, tt := range tests {
		name := strings.TrimSpace(tt.file + " " + strings.Join(tt.args, " "))
		t.Run(name, func(t *testing.T) {
			cmd := tt.command
			if cmd == "" {
				cmd = "message"
			}
			args := append([]string{cmd, fixture(tt.file), "--resolver", resolver, "--json"}, tt.args...)
			res := mailauthprobe(t, nil, args...)
			if res.code != tt.code {
				t.Fatalf("exit code = %d, want %d\n%s", res.code, tt.code, res.stderr)
			}
			r := parseReport(t, res.stdout)
			if r.Message == nil {
				t.Fatal("no message section")
			}
			if r.Message.SPF.Result != tt.spf || r.Message.DMARC.Result != tt.dmarc {
				t.Errorf("spf = %q, dmarc = %q; want %q, %q", r.Message.SPF.Result, r.Message.DMARC.Result, tt.spf, tt.dmarc)
			}
			var dkim []string
			for _, d := range r.Message.DKIM {
				dkim = append(dkim, d.Result)
			}
			if !slices.Equal(dkim, tt.dkim) {
				t.Errorf("dkim = %v, want %v", dkim, tt.dkim)
			}
			ids := r.ids()
			for _, id := range tt.want {
				if !slices.Contains(ids, id) {
					t.Errorf("missing finding %s in %v", id, ids)
				}
			}
			for _, id := range tt.forbidden {
				if slices.Contains(ids, id) {
					t.Errorf("unexpected finding %s", id)
				}
			}
		})
	}
}

func TestOversizedHeaders(t *testing.T) {
	res := mailauthprobe(t, nil, "message", fixture("oversized-headers.eml"), "--resolver", resolver, "--json")
	if res.code != 3 {
		t.Fatalf("exit code = %d, want 3", res.code)
	}
	r := parseReport(t, res.stdout)
	if len(r.Errors) != 1 || r.Errors[0].Kind != "input" || !strings.Contains(res.stderr, "header section size") {
		t.Errorf("errors = %+v, stderr = %s", r.Errors, res.stderr)
	}
	text := mailauthprobe(t, nil, "message", fixture("oversized-headers.eml"), "--resolver", resolver)
	if text.code != 3 || text.stdout != "" {
		t.Errorf("text mode: code %d, stdout %q", text.code, text.stdout)
	}
}

func TestMessageFromStdin(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root, fixture("valid.eml")))
	if err != nil {
		t.Fatal(err)
	}
	res := mailauthprobe(t, raw, "message", "-", "--resolver", resolver, "--json")
	if res.code != 0 {
		t.Fatalf("exit code = %d: %s", res.code, res.stderr)
	}
	if r := parseReport(t, res.stdout); r.Message.DMARC.Result != "pass" {
		t.Errorf("dmarc = %s", r.Message.DMARC.Result)
	}
}

func TestDomainScans(t *testing.T) {
	tests := []struct {
		domain string
		args   []string
		code   int
		want   []string
	}{
		{"test.example", []string{"--dkim-selector", "s2026"}, 0, []string{"MAIL-MX-015", "MAIL-SPF-022", "MAIL-DMARC-017", "MAIL-DKIM-012"}},
		{"test.example", nil, 0, []string{"MAIL-DKIM-001"}},
		{"test.example", []string{"--fail-on", "low"}, 1, nil},
		{"lookups.example", nil, 0, []string{"MAIL-SPF-005"}},
		{"loop.example", nil, 0, []string{"MAIL-SPF-004"}},
		{"none.example", nil, 0, []string{"MAIL-DMARC-004", "MAIL-SPF-009"}},
		{"strict.example", nil, 0, []string{"MAIL-DMARC-016"}},
		{"nonexistent.example", nil, 0, []string{"MAIL-MX-003", "MAIL-SPF-001", "MAIL-DMARC-001"}},
		{"garbled.example", nil, 4, []string{"MAIL-DNS-001"}},
		{"broken.example", []string{"--timeout", "3s"}, 4, nil},
	}
	for _, tt := range tests {
		t.Run(strings.TrimSpace(tt.domain+" "+strings.Join(tt.args, " ")), func(t *testing.T) {
			args := append([]string{"domain", tt.domain, "--resolver", resolver, "--json"}, tt.args...)
			res := mailauthprobe(t, nil, args...)
			if res.code != tt.code {
				t.Fatalf("exit code = %d, want %d\nstderr: %s\nstdout: %s", res.code, tt.code, res.stderr, res.stdout)
			}
			r := parseReport(t, res.stdout)
			for _, id := range tt.want {
				if !slices.Contains(r.ids(), id) {
					t.Errorf("missing finding %s in %v", id, r.ids())
				}
			}
			if tt.code == 4 && (len(r.Errors) == 0 || r.Errors[0].Kind != "dns") {
				t.Errorf("errors = %+v", r.Errors)
			}
		})
	}
}

func TestUsageAndMetaCommands(t *testing.T) {
	tests := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--help"}, 0, "Exit codes:"},
		{[]string{"version"}, 0, "mailauthprobe v0.0.0-functional"},
		{[]string{"version", "--json"}, 0, `"version": "v0.0.0-functional"`},
		{[]string{"completion", "bash"}, 0, "__start_mailauthprobe"},
		{[]string{"completion", "zsh"}, 0, "#compdef mailauthprobe"},
		{[]string{"completion", "fish"}, 0, "complete -c mailauthprobe"},
		{[]string{"domain"}, 2, "expects a domain name"},
		{[]string{"message"}, 2, "expects a file name"},
		{[]string{"domain", "example.com", "--fail-on", "sometimes"}, 2, "invalid --fail-on"},
		{[]string{"frobnicate"}, 2, "unknown command"},
		{[]string{"message", "testdata/messages/missing.eml"}, 3, "cannot open message"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			res := mailauthprobe(t, nil, tt.args...)
			if res.code != tt.code || !strings.Contains(res.stdout+res.stderr, tt.want) {
				t.Errorf("code = %d (want %d), output lacks %q:\n%s%s", res.code, tt.code, tt.want, res.stdout, res.stderr)
			}
		})
	}
}

var versionRE = regexp.MustCompile(`"version": "[^"]*"`)

// TestGolden compares complete outputs with files in testdata/golden. Run
// with -update after intentional output changes and review the diff.
func TestGolden(t *testing.T) {
	type golden struct {
		name string
		args []string
	}
	var cases []golden
	entries, err := os.ReadDir(filepath.Join(root, "testdata", "messages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "oversized") {
			continue
		}
		cmd := "message"
		if strings.HasSuffix(name, ".txt") {
			cmd = "headers"
		}
		cases = append(cases, golden{name + ".json", []string{cmd, fixture(name), "--json"}})
	}
	cases = append(cases,
		golden{"valid.eml.txt", []string{"message", fixture("valid.eml"), "--verbose"}},
		golden{"dmarc-reject.eml.txt", []string{"message", fixture("dmarc-reject.eml")}},
		golden{"domain-test.example.json", []string{"domain", "test.example", "--dkim-selector", "s2026", "--json"}},
		golden{"domain-test.example.txt", []string{"domain", "test.example", "--dkim-selector", "s2026"}},
		golden{"domain-lookups.example.txt", []string{"domain", "lookups.example"}},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mailauthprobe(t, nil, append(c.args, "--resolver", resolver)...)
			got := versionRE.ReplaceAllString(res.stdout, `"version": "VERSION"`)
			path := filepath.Join(root, "testdata", "golden", c.name)
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./test/functional -update)", err)
			}
			if got != string(want) {
				t.Errorf("output differs from %s (run: go test ./test/functional -update and review the diff)\n%s", c.name, firstDiff(string(want), got))
			}
		})
	}
}

func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < max(len(wl), len(gl)); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return fmt.Sprintf("line %d:\n  want: %s\n  got:  %s", i+1, w, g)
		}
	}
	return ""
}
