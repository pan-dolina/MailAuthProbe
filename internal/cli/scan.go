package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marcindolinski/mailauthprobe/internal/analyzer"
	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
	"github.com/marcindolinski/mailauthprobe/internal/netutil"
	"github.com/marcindolinski/mailauthprobe/internal/report"
)

type messageFlags struct {
	sourceIP string
	helo     string
	mailFrom string
}

func (a *App) newDomainCommand() *cobra.Command {
	var selectors []string
	cmd := &cobra.Command{
		Use:   "domain <domain>",
		Short: "Audit the mail security configuration of a domain",
		Long: `Audit MX, SPF, DKIM, DMARC, MTA-STS and TLS-RPT for a domain.

DKIM selectors cannot be discovered from DNS; pass the selectors in use with
--dkim-selector (repeatable) to audit their keys.`,
		Example: `  mailauthprobe domain example.com
  mailauthprobe domain example.com --dkim-selector selector1 --dkim-selector selector2
  mailauthprobe domain example.com --json --fail-on high`,
		Args: exactArgs(1, "a domain name"),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := strings.TrimSuffix(strings.TrimSpace(args[0]), ".")
			if _, err := netip.ParseAddr(domain); err == nil || !dnsresolver.ValidDomain(domain) || !strings.Contains(domain, ".") {
				return usageErrorf("%q is not a fully qualified domain name", args[0])
			}
			for _, s := range selectors {
				if s == "" || strings.ContainsAny(s, " \t") || !dnsresolver.ValidDomain(s+"._domainkey."+domain) {
					return usageErrorf("invalid DKIM selector %q", s)
				}
			}
			opts, cancel, err := a.analyzerOptions(cmd.Context())
			if err != nil {
				return err
			}
			defer cancel()
			opts.DKIMSelectors = selectors
			rep := analyzer.Domain(opts.ctx, domain, opts.Options)
			return a.finish(rep, nil)
		},
	}
	cmd.Flags().StringSliceVar(&selectors, "dkim-selector", nil, "DKIM selector to audit (repeatable or comma-separated)")
	return cmd
}

func (a *App) newMessageCommand(headersOnly bool) *cobra.Command {
	var mf messageFlags
	use, short, long, example := "message <file|->", "Analyse an e-mail message",
		`Analyse a complete RFC 5322 message: parse the Received chain, verify every
DKIM signature cryptographically, evaluate SPF and DMARC independently and
compare the results with the Authentication-Results headers.

SPF needs the SMTP client address, HELO name and MAIL FROM. They are inferred
from Received, Received-SPF and Return-Path headers when not given with
--source-ip, --helo and --mail-from; inferred values are marked as such.

The message is treated as hostile input: attachments are never extracted,
HTML is never rendered and links are never followed.`,
		`  mailauthprobe message suspicious.eml
  cat suspicious.eml | mailauthprobe message -
  mailauthprobe message mail.eml --source-ip 192.0.2.10 --helo mail.example.com --mail-from bounce@example.com`
	if headersOnly {
		use, short = "headers <file|->", "Analyse a message header section"
		long = `Analyse a file that contains only the header section of a message, for
example headers copied from a mail client. DKIM header signatures are
verified, but body hashes cannot be checked.`
		example = `  mailauthprobe headers headers.txt
  pbpaste | mailauthprobe headers -`
	}
	cmd := &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Args:    exactArgs(1, "a file name or - for standard input"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := mf.validate(); err != nil {
				return err
			}
			var in io.Reader
			target := args[0]
			if target == "-" {
				in = a.Stdin
			} else {
				f, err := os.Open(target) // #nosec G304 -- the operator chooses which file to analyse
				if err != nil {
					return withCode(ExitInput, fmt.Errorf("cannot open message: %w", err))
				}
				defer f.Close()
				if st, err := f.Stat(); err == nil && st.IsDir() {
					return withCode(ExitInput, fmt.Errorf("%s is a directory", target))
				}
				in = f
			}
			opts, cancel, err := a.analyzerOptions(cmd.Context())
			if err != nil {
				return err
			}
			defer cancel()
			opts.SourceIP, opts.HELO, opts.MailFrom = mf.sourceIP, mf.helo, mf.mailFrom
			rep, err := analyzer.Message(opts.ctx, in, target, headersOnly, opts.Options)
			return a.finish(rep, err)
		},
	}
	f := cmd.Flags()
	f.StringVar(&mf.sourceIP, "source-ip", "", "SMTP client IP address (overrides the value inferred from headers)")
	f.StringVar(&mf.helo, "helo", "", "HELO/EHLO name used by the client")
	f.StringVar(&mf.mailFrom, "mail-from", "", "envelope sender (MAIL FROM); use <> for a null sender")
	return cmd
}

func (mf *messageFlags) validate() error {
	if mf.sourceIP != "" {
		if _, err := netip.ParseAddr(mf.sourceIP); err != nil {
			return usageErrorf("invalid --source-ip %q", mf.sourceIP)
		}
	}
	if mf.helo != "" && !dnsresolver.ValidDomain(mf.helo) && !netutil.IsHostname(mf.helo) {
		return usageErrorf("invalid --helo %q", mf.helo)
	}
	if mf.mailFrom != "" && mf.mailFrom != "<>" {
		addr := strings.Trim(mf.mailFrom, "<>")
		at := strings.LastIndexByte(addr, '@')
		if at <= 0 || !dnsresolver.ValidDomain(addr[at+1:]) {
			return usageErrorf("invalid --mail-from %q (want local@domain or <>)", mf.mailFrom)
		}
	}
	return nil
}

func exactArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return usageErrorf("%s expects %s", cmd.Name(), what)
		}
		return nil
	}
}

type scanOptions struct {
	analyzer.Options
	ctx context.Context
}

func (a *App) analyzerOptions(parent context.Context) (scanOptions, context.CancelFunc, error) {
	queryTimeout := min(dnsresolver.DefaultQueryTimeout, a.opts.timeout)
	res, err := dnsresolver.New(dnsresolver.Options{Server: a.opts.resolver, Timeout: queryTimeout})
	if err != nil {
		return scanOptions{}, nil, usageErrorf("invalid --resolver: %v", err)
	}
	ctx, cancel := context.WithTimeout(parent, a.opts.timeout)
	return scanOptions{
		Options: analyzer.Options{Resolver: res, HTTPTimeout: min(10*time.Second, a.opts.timeout)},
		ctx:     ctx,
	}, cancel, nil
}

// finish renders the report and maps the outcome to an exit code. Precedence
// when several conditions apply: input error (3), DNS/network error (4),
// --fail-on threshold (1).
func (a *App) finish(rep *report.Report, scanErr error) error {
	if !a.opts.quiet {
		var err error
		if a.opts.json {
			err = report.WriteJSON(a.Stdout, rep)
		} else if scanErr == nil {
			err = report.WriteText(a.Stdout, rep, report.TextOptions{Color: a.useColor(), Verbose: a.opts.verbose})
		}
		if err != nil {
			return withCode(ExitInternal, fmt.Errorf("writing report: %w", err))
		}
	}

	var inputErr *analyzer.InputError
	switch {
	case errors.As(scanErr, &inputErr):
		return withCode(ExitInput, inputErr)
	case scanErr != nil:
		return withCode(ExitInternal, scanErr)
	case rep.HasErrorKind(report.ErrorDNS):
		if a.opts.json || a.opts.quiet {
			return withCode(ExitNetwork, errors.New("DNS or network failures made the results incomplete"))
		}
		return silentExit(ExitNetwork)
	}
	if a.opts.failOn != "none" {
		threshold, _ := findings.ParseSeverity(a.opts.failOn)
		if n := len(findings.AtLeast(rep.Findings, threshold)); n > 0 {
			if a.opts.verbose {
				fmt.Fprintf(a.Stderr, "mailauthprobe: %d finding(s) at or above %s\n", n, threshold)
			}
			return silentExit(ExitFindings)
		}
	}
	return nil
}

func (a *App) useColor() bool {
	if a.opts.noColor || a.Getenv("NO_COLOR") != "" || a.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := a.Stdout.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
