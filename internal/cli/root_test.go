package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	app := &App{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
		Getenv: func(string) string { return "" },
	}
	code = app.Execute(context.Background(), args)
	return out.String(), errb.String(), code
}

func TestGlobalFlagValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"help", []string{"--help"}, ExitOK, "Exit codes:"},
		{"unknown flag", []string{"--bogus"}, ExitUsage, "unknown flag"},
		{"unknown command", []string{"frobnicate"}, ExitUsage, "unknown command"},
		{"bad fail-on", []string{"version", "--fail-on", "severe"}, ExitUsage, "invalid --fail-on"},
		{"fail-on case insensitive", []string{"version", "--fail-on", "HIGH"}, ExitOK, ""},
		{"quiet and verbose", []string{"version", "-q", "-v"}, ExitUsage, "mutually exclusive"},
		{"negative timeout", []string{"version", "--timeout", "-1s"}, ExitUsage, "--timeout must be positive"},
		{"version extra args", []string{"version", "extra"}, ExitUsage, "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := run(t, tt.args...)
			if code != tt.code {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, tt.code, stderr)
			}
			if tt.want != "" && !strings.Contains(stdout+stderr, tt.want) {
				t.Errorf("output does not contain %q:\nstdout: %s\nstderr: %s", tt.want, stdout, stderr)
			}
		})
	}
}

func TestVersionJSON(t *testing.T) {
	stdout, _, code := run(t, "version", "--json")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	for _, key := range []string{"version", "go_version", "platform"} {
		if _, ok := v[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
}

func TestCompletion(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		stdout, stderr, code := run(t, "completion", shell)
		if code != ExitOK || !strings.Contains(stdout, "mailauthprobe") {
			t.Errorf("completion %s: code=%d stderr=%s", shell, code, stderr)
		}
	}
}
