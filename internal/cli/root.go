// Package cli implements the mailauthprobe command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// globalOptions holds flags shared by all subcommands.
type globalOptions struct {
	json     bool
	quiet    bool
	verbose  bool
	noColor  bool
	failOn   string
	timeout  time.Duration
	resolver string
}

// App wires the command tree to its I/O streams.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Getenv is used for NO_COLOR and similar environment lookups.
	Getenv func(string) string

	opts globalOptions
}

// NewApp returns an App bound to the process streams.
func NewApp() *App {
	return &App{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv}
}

// Execute runs the CLI with the given arguments and returns the exit code.
func (a *App) Execute(ctx context.Context, args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(a.Stderr, "mailauthprobe: internal error: %v\n", r)
			code = ExitInternal
		}
	}()
	root := a.newRootCommand()
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	code = ExitCode(err)
	if err != nil {
		var ee *exitError
		if !errors.As(err, &ee) || ee.err != nil {
			fmt.Fprintf(a.Stderr, "mailauthprobe: %v\n", err)
		}
		if code == ExitUsage {
			fmt.Fprintln(a.Stderr, "Run 'mailauthprobe --help' for usage.")
		}
	}
	return code
}

func (a *App) newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "mailauthprobe",
		Short: "Audit mail authentication configuration and analyse messages",
		Long: `MailAuthProbe audits the mail security configuration of a domain
(MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT) and independently verifies SPF,
DKIM and DMARC for real messages.

Exit codes:
  0  scan completed, no finding reached the --fail-on threshold
  1  at least one finding reached the --fail-on threshold
  2  invalid arguments
  3  input could not be read or parsed, or exceeded safety limits
  4  DNS or network failure prevented a reliable result
  5  internal error

When several conditions apply, the most specific code wins: 5, then 3,
then 4, then 1.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.validateGlobalOptions()
		},
	}
	root.SetIn(a.Stdin)
	root.SetOut(a.Stdout)
	root.SetErr(a.Stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return withCode(ExitUsage, err)
	})

	pf := root.PersistentFlags()
	pf.BoolVar(&a.opts.json, "json", false, "write a machine-readable JSON report")
	pf.BoolVarP(&a.opts.quiet, "quiet", "q", false, "suppress the human-readable report; rely on the exit code")
	pf.BoolVarP(&a.opts.verbose, "verbose", "v", false, "include passing checks and raw records in the report")
	pf.BoolVar(&a.opts.noColor, "no-color", false, "disable colored output (also honours NO_COLOR)")
	pf.StringVar(&a.opts.failOn, "fail-on", "none", "exit with status 1 if a finding has at least this severity: none, info, low, medium, high, critical")
	pf.DurationVar(&a.opts.timeout, "timeout", 30*time.Second, "overall deadline for the scan")
	pf.StringVar(&a.opts.resolver, "resolver", "", "DNS resolver address (host or host:port); defaults to the system resolver")

	root.AddCommand(
		a.newDomainCommand(),
		a.newMessageCommand(false),
		a.newMessageCommand(true),
		a.newVersionCommand(),
	)
	return root
}

var failOnValues = []string{"none", "info", "low", "medium", "high", "critical"}

func (a *App) validateGlobalOptions() error {
	if a.opts.quiet && a.opts.verbose {
		return usageErrorf("--quiet and --verbose are mutually exclusive")
	}
	if a.opts.timeout <= 0 {
		return usageErrorf("--timeout must be positive, got %s", a.opts.timeout)
	}
	valid := false
	for _, v := range failOnValues {
		if strings.EqualFold(a.opts.failOn, v) {
			a.opts.failOn = v
			valid = true
			break
		}
	}
	if !valid {
		return usageErrorf("invalid --fail-on value %q (want one of: %s)", a.opts.failOn, strings.Join(failOnValues, ", "))
	}
	return nil
}
