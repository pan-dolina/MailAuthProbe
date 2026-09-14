package report

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marcindolinski/mailauthprobe/internal/findings"
	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
	"github.com/marcindolinski/mailauthprobe/internal/spf"
)

// TextOptions control human-readable rendering.
type TextOptions struct {
	Color   bool
	Verbose bool
	// Width is the target line width for wrapping descriptions; 0 means 100.
	Width int
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiMag    = "\x1b[35m"
	ansiCyan   = "\x1b[36m"
)

type textWriter struct {
	w    io.Writer
	opts TextOptions
	err  error
}

// styled is text that is safe to write to a terminal: untrusted content in it
// has been escaped and any escape sequences were added by the renderer.
type styled string

// printf writes formatted output. String arguments are treated as untrusted
// and escaped; styled arguments are written as they are.
func (t *textWriter) printf(format string, args ...any) {
	if t.err != nil {
		return
	}
	for i, a := range args {
		switch v := a.(type) {
		case styled:
			args[i] = string(v)
		case string:
			args[i] = escapeTerminal(v)
		}
	}
	_, t.err = fmt.Fprintf(t.w, format, args...)
}

// plain escapes untrusted text for inclusion in styled output.
func plain(s string) styled { return styled(escapeTerminal(s)) }

func (t *textWriter) style(code, s string) styled {
	if !t.opts.Color || s == "" {
		return plain(s)
	}
	return styled(code + escapeTerminal(s) + ansiReset)
}

// escapeTerminal neutralises data from messages, DNS and HTTP before it is
// printed: control characters (which include the ESC that starts terminal
// escape sequences), DEL, C1 controls, invalid UTF-8 and Unicode
// bidirectional overrides are replaced by visible escapes. Without this a
// crafted Subject header or TXT record could rewrite the verdicts shown on
// screen.
func escapeTerminal(s string) string {
	clean := true
	for _, r := range s {
		if needsEscape(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == utf8.RuneError && len(s[i:]) > 0 && !strings.HasPrefix(s[i:], "\uFFFD"):
			fmt.Fprintf(&b, "\\x%02x", s[i])
		case r < 0x80 && needsEscape(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		case needsEscape(r):
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsEscape(r rune) bool {
	switch {
	case r == '\t':
		return false
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f:
		return true
	case r == utf8.RuneError:
		return true
	}
	return false
}

func (t *textWriter) heading(s string) {
	t.printf("\n%s\n", t.style(ansiBold, s))
}

func (t *textWriter) kv(key string, value styled) {
	if value == "" {
		return
	}
	t.printf("  %-18s %s\n", key+":", value)
}

var severityColors = map[findings.Severity]string{
	findings.SeverityCritical: ansiBold + ansiRed,
	findings.SeverityHigh:     ansiRed,
	findings.SeverityMedium:   ansiYellow,
	findings.SeverityLow:      ansiCyan,
	findings.SeverityInfo:     ansiBlue,
	findings.SeverityPass:     ansiGreen,
}

func (t *textWriter) severity(s findings.Severity) styled {
	label := fmt.Sprintf("%-8s", strings.ToUpper(s.String()))
	return t.style(severityColors[s], label)
}

func (t *textWriter) result(r string) styled {
	switch r {
	case "pass":
		return t.style(ansiGreen, r)
	case "fail", "permerror":
		return t.style(ansiRed, r)
	case "softfail", "temperror", "neutral", "quarantine":
		return t.style(ansiYellow, r)
	case "", "none":
		return t.style(ansiDim, "none")
	}
	return plain(r)
}

// WriteText renders rep for a terminal.
func WriteText(w io.Writer, rep *Report, opts TextOptions) error {
	if opts.Width <= 0 {
		opts.Width = 100
	}
	t := &textWriter{w: w, opts: opts}
	t.printf("%s %s: %s\n", t.style(ansiBold, "MailAuthProbe"), rep.Kind, t.style(ansiBold, rep.Target))

	switch {
	case rep.Domain != nil:
		t.domain(rep.Domain)
	case rep.Message != nil:
		t.message(rep.Message)
	}
	t.findings(rep)
	t.summary(rep)
	return t.err
}

func (t *textWriter) summary(rep *Report) {
	t.heading("Summary")
	var parts []string
	for _, s := range findings.Severities() {
		n := rep.Summary.Counts[s.String()]
		label := plain(fmt.Sprintf("%d %s", n, s))
		if n > 0 {
			label = t.style(severityColors[s], string(label))
		}
		parts = append(parts, string(label))
	}
	t.printf("  %s\n", styled(strings.Join(parts, ", ")))
	t.printf("  %s\n", t.style(ansiDim, fmt.Sprintf("%d DNS queries", rep.Summary.DNSQueries)))
	for _, e := range rep.Errors {
		t.printf("  %s %s: %s\n", t.style(ansiRed, "error"), e.Component, e.Message)
	}
}

func (t *textWriter) findings(rep *Report) {
	var shown []findings.Finding
	hiddenPass := 0
	for _, f := range rep.Findings {
		if f.Severity == findings.SeverityPass && !t.opts.Verbose {
			hiddenPass++
			continue
		}
		shown = append(shown, f)
	}
	t.heading("Findings")
	if len(shown) == 0 {
		t.printf("  No findings.\n")
	}
	for _, f := range shown {
		t.printf("  %s %s  %s\n", t.severity(f.Severity), t.style(ansiDim, f.ID), t.style(ansiBold, f.Title))
		indent := strings.Repeat(" ", 11)
		desc := f.Description
		if f.Subject != "" && !strings.Contains(desc, f.Subject) {
			desc = f.Subject + ": " + desc
		}
		for _, line := range wrap(desc, t.opts.Width-len(indent)) {
			t.printf("%s%s\n", indent, line)
		}
		limit := 5
		if t.opts.Verbose {
			limit = len(f.Evidence)
		}
		for i, ev := range f.Evidence {
			if i == limit {
				t.printf("%s%s\n", indent, t.style(ansiDim, fmt.Sprintf("… %d more (use --verbose)", len(f.Evidence)-limit)))
				break
			}
			t.printf("%s%s %s\n", indent, t.style(ansiDim, "│"), ev)
		}
		if f.Recommendation != "" && f.Severity > findings.SeverityInfo {
			for i, line := range wrap(f.Recommendation, t.opts.Width-len(indent)-2) {
				prefix := styled("  ")
				if i == 0 {
					prefix = t.style(ansiMag, "→ ")
				}
				t.printf("%s%s%s\n", indent, prefix, line)
			}
		}
		if t.opts.Verbose {
			for _, ref := range f.References {
				t.printf("%s%s\n", indent, t.style(ansiDim, ref))
			}
		}
	}
	if hiddenPass > 0 {
		t.printf("  %s\n", t.style(ansiDim, fmt.Sprintf("%d passing check(s) hidden; use --verbose to show them.", hiddenPass)))
	}
}

func wrap(s string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		var cur strings.Builder
		for _, w := range words {
			if cur.Len() > 0 && cur.Len()+1+len(w) > width {
				lines = append(lines, cur.String())
				cur.Reset()
			}
			if cur.Len() > 0 {
				cur.WriteByte(' ')
			}
			cur.WriteString(w)
		}
		if cur.Len() > 0 {
			lines = append(lines, cur.String())
		}
	}
	return lines
}

func (t *textWriter) domain(d *Domain) {
	if d.MX != nil {
		t.heading("MX")
		switch {
		case d.MX.NullMX:
			t.printf("  null MX (the domain does not accept mail)\n")
		case len(d.MX.Hosts) == 0:
			t.printf("  none\n")
		}
		for _, h := range d.MX.Hosts {
			if h.Name == "." {
				continue
			}
			var addrs []string
			for _, a := range append(h.IPv4, h.IPv6...) {
				addrs = append(addrs, a.String())
			}
			pref := fmt.Sprintf("%5d", h.Preference)
			if d.MX.Implicit {
				pref = "impl."
			}
			line := plain(strings.TrimRight(fmt.Sprintf("  %s  %-32s %s", pref, h.Name, strings.Join(addrs, ", ")), " "))
			if h.CNAME != "" {
				line += t.style(ansiYellow, " (CNAME → "+h.CNAME+")")
			}
			if h.Error != "" {
				line += t.style(ansiRed, " ("+h.Error+")")
			}
			t.printf("%s\n", line)
		}
	}
	if d.SPF != nil {
		t.heading("SPF")
		if d.SPF.Record == "" {
			t.printf("  no record\n")
		} else {
			t.printf("  %s\n", d.SPF.Record)
			t.printf("  DNS lookups: %d/10, void lookups: %d/2\n", d.SPF.TotalLookups, d.SPF.VoidLookups)
			if d.SPF.Tree != nil && (len(d.SPF.Tree.Children) > 0 || t.opts.Verbose) {
				t.printf("  Dependency tree:\n")
				t.spfTree(d.SPF.Tree, "  ", "", true)
			}
		}
	}
	if d.DMARC != nil && d.DMARC.Discovery != nil {
		t.heading("DMARC")
		disc := d.DMARC.Discovery
		switch {
		case len(disc.Records) == 0:
			t.printf("  no record\n")
		default:
			for _, r := range disc.Records {
				t.printf("  _dmarc.%s: %s\n", disc.PolicyDomain, r)
			}
			if rec := disc.Policy(); rec != nil {
				t.printf("  policy %s, subdomains %s, pct %d, adkim=%s, aspf=%s\n", t.result(string(rec.Policy)), rec.EffectiveSubdomainPolicy(), rec.Percent, rec.ADKIM, rec.ASPF)
			}
		}
	}
	if d.DKIM != nil {
		t.heading("DKIM")
		if len(d.DKIM.Selectors) == 0 {
			t.printf("  no selectors checked (use --dkim-selector)\n")
		}
		for _, s := range d.DKIM.Selectors {
			switch {
			case s.Key != nil && s.Key.Revoked:
				t.printf("  %s: revoked\n", s.Name)
			case s.Key != nil:
				t.printf("  %s: %s %d bits\n", s.Name, strings.ToUpper(s.Key.KeyType), s.Key.KeyBits)
			default:
				t.printf("  %s: %s\n", s.Name, t.style(ansiRed, s.Error))
			}
		}
	}
	if d.MTASTS != nil {
		t.heading("MTA-STS")
		switch {
		case d.MTASTS.Policy != nil:
			p := d.MTASTS.Policy
			t.printf("  mode %s, max_age %d, mx %s\n", p.Mode, p.MaxAge, strings.Join(p.MX, ", "))
		case len(d.MTASTS.Records) > 0:
			t.printf("  %s\n", d.MTASTS.Records[0])
			if d.MTASTS.Error != "" {
				t.printf("  %s\n", t.style(ansiRed, d.MTASTS.Error))
			}
		default:
			t.printf("  not deployed\n")
		}
	}
	if d.TLSRPT != nil {
		t.heading("TLS-RPT")
		if d.TLSRPT.Record != nil {
			t.printf("  %s\n", strings.Join(d.TLSRPT.Record.RUA, ", "))
		} else if len(d.TLSRPT.Records) > 0 {
			t.printf("  %s\n", strings.Join(d.TLSRPT.Records, " | "))
		} else {
			t.printf("  not configured\n")
		}
	}
}

func (t *textWriter) spfTree(n *spf.Node, indent, prefix string, last bool) {
	label := n.Domain
	if n.Via != "" {
		label = n.Via
	}
	counts := fmt.Sprintf("%d lookup(s)", n.Lookups)
	if n.TotalLookups != n.Lookups {
		counts += fmt.Sprintf(", %d with includes", n.TotalLookups)
	}
	info := t.style(ansiDim, "("+counts+")")
	switch {
	case n.Loop:
		info = t.style(ansiRed, "(loop)")
	case n.Dynamic:
		info = t.style(ansiDim, "(depends on message data)")
	case n.Error != "":
		info = t.style(ansiDim, "("+counts+", ") + t.style(ansiRed, n.Error) + t.style(ansiDim, ")")
	}
	branch := ""
	if prefix != "" || n.Via != "" {
		branch = "├─ "
		if last {
			branch = "└─ "
		}
	}
	t.printf("%s%s%s%s %s\n", indent, prefix, branch, label, info)
	childPrefix := prefix
	if branch != "" {
		if last {
			childPrefix += "   "
		} else {
			childPrefix += "│  "
		}
	}
	for i, c := range n.Children {
		t.spfTree(c, indent, childPrefix, i == len(n.Children)-1)
	}
}

func first(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	if len(vals) > 1 {
		return vals[0] + fmt.Sprintf("  (+%d more)", len(vals)-1)
	}
	return vals[0]
}

func (t *textWriter) message(m *Message) {
	t.heading("Headers")
	h := m.Headers
	t.kv("From", plain(first(h.From)))
	t.kv("Sender", plain(first(h.Sender)))
	t.kv("Reply-To", plain(first(h.ReplyTo)))
	t.kv("Return-Path", plain(first(h.ReturnPath)))
	t.kv("To", plain(first(h.To)))
	t.kv("Subject", plain(first(h.Subject)))
	t.kv("Date", plain(first(h.Date)))
	t.kv("Message-ID", plain(first(h.MessageID)))
	if m.MIME != nil && t.opts.Verbose {
		t.kv("Content-Type", plain(m.MIME.ContentType))
	}

	t.heading("Verdicts")
	spfRes := plain("not evaluated")
	if m.SPF != nil && m.SPF.Result != "" {
		spfRes = t.result(string(m.SPF.Result)) + plain(" ("+m.SPF.Domain+")")
		if m.SPF.Inputs.IP != nil && m.SPF.Inputs.IP.Inferred {
			spfRes += t.style(ansiDim, " inputs inferred")
		}
	}
	t.kv("SPF", spfRes)
	passing := 0
	for _, v := range m.DKIM {
		if v.Result == "pass" {
			passing++
		}
	}
	dkimRes := t.result("none")
	if len(m.DKIM) > 0 {
		res := "fail"
		if passing > 0 {
			res = "pass"
		}
		dkimRes = t.result(res) + plain(fmt.Sprintf(" (%d of %d signatures valid)", passing, len(m.DKIM)))
	}
	t.kv("DKIM", dkimRes)
	if m.DMARC != nil {
		d := t.result(m.DMARC.Result)
		if m.DMARC.FromDomain != "" {
			detail := " (" + m.DMARC.FromDomain
			if m.DMARC.Policy != "" {
				detail += ", policy " + string(m.DMARC.Policy)
			}
			d += plain(detail + ")")
		}
		t.kv("DMARC", d)
	}

	if m.Received != nil && len(m.Received.Hops) > 0 {
		t.heading("Transport path (origin first)")
		for _, hop := range m.Received.Hops {
			from := "?"
			switch {
			case hop.HELO != nil:
				from = hop.HELO.Value
			case hop.FromHost != nil:
				from = hop.FromHost.Value
			}
			if hop.IP != nil {
				from += " [" + hop.IP.Value + "]"
			}
			if hop.HELO == nil && hop.FromHost == nil && hop.IP == nil {
				from = "(local)"
			}
			by := "?"
			if hop.By != nil {
				by = hop.By.Value
			}
			ts := ""
			if hop.Timestamp != nil {
				ts = hop.Timestamp.UTC().Format(time.RFC3339)
			}
			t.printf("  #%-2d %s → %s  %s\n", hop.Index, from, by, t.style(ansiDim, ts))
			var details []string
			if hop.Protocol != "" {
				details = append(details, "with "+hop.Protocol)
			}
			if hop.TLS != nil {
				tls := "no TLS"
				if hop.TLS.Used {
					tls = "TLS"
					if hop.TLS.Version != "" {
						tls += " " + hop.TLS.Version
					}
				}
				details = append(details, tls+" ("+hop.TLS.Source+")")
			}
			if hop.HELO != nil {
				details = append(details, "helo "+hop.HELO.Source)
			}
			if hop.ReverseDNS != nil {
				details = append(details, "rdns "+hop.ReverseDNS.Value+" ("+hop.ReverseDNS.Source+")")
			}
			if hop.Delay != nil && *hop.Delay != 0 {
				details = append(details, "+"+hop.Delay.String())
			}
			if len(details) > 0 {
				t.printf("       %s\n", t.style(ansiDim, strings.Join(details, ", ")))
			}
		}
	}

	if len(m.DKIM) > 0 {
		t.heading("DKIM signatures")
		for _, v := range m.DKIM {
			t.printf("  #%d %s d=%s s=%s %s %s\n", v.Index, t.result(string(v.Result)), v.Domain, v.Selector, v.Algorithm, v.Canonicalization)
			t.printf("     %s\n", t.style(ansiDim, v.Reason))
			if t.opts.Verbose && len(v.SignedHeaders) > 0 {
				t.printf("     %s\n", t.style(ansiDim, "h="+strings.Join(v.SignedHeaders, ":")))
			}
		}
	}

	if m.SPF != nil && m.SPF.Result != "" {
		t.heading("SPF")
		in := m.SPF.Inputs
		for _, x := range []struct {
			name string
			in   *spf.Input
		}{{"client IP", in.IP}, {"HELO", in.HELO}, {"MAIL FROM", in.MailFrom}} {
			if x.in == nil {
				continue
			}
			src := x.in.Source
			if x.in.Inferred {
				src += ", inferred"
			}
			t.kv(x.name, plain(x.in.Value)+t.style(ansiDim, " ("+src+")"))
		}
		if in.NullSender {
			t.kv("MAIL FROM", "<> (null sender)")
		}
		for _, ev := range []*spf.Evaluation{m.SPF.MailFrom, m.SPF.HELO} {
			if ev == nil {
				continue
			}
			line := fmt.Sprintf("%s: %s", ev.Domain, t.result(string(ev.Result)))
			if ev.MatchedTerm != "" {
				line += fmt.Sprintf(" via %q", ev.MatchedTerm)
			}
			t.printf("  %s\n", line)
			if t.opts.Verbose {
				for _, step := range ev.Trace {
					t.printf("     %s%s %s %s\n", strings.Repeat("  ", step.Depth), step.Domain, step.Term, t.style(ansiDim, step.Note))
				}
			}
		}
	}

	if len(m.AuthResults) > 0 {
		t.heading("Authentication-Results (as received)")
		for _, p := range m.AuthResults {
			if p.Header == nil {
				t.printf("  #%d %s\n", p.Index, t.style(ansiRed, "unparseable: "+p.Error))
				continue
			}
			var rs []string
			for _, r := range p.Header.Results {
				rs = append(rs, string(plain(r.Method+"=")+t.result(r.Result)))
			}
			id := p.Header.AuthServID
			if id == "" {
				id = "(no authserv-id)"
			}
			t.printf("  #%d %s: %s\n", p.Index, id, styled(strings.Join(rs, " ")))
		}
	}

	if m.MIME != nil && (len(m.MIME.Parts) > 0 || t.opts.Verbose) {
		t.heading("MIME structure")
		t.mimeTree(m.MIME, "  ")
	}
}

func (t *textWriter) mimeTree(p *mailparser.Part, indent string) {
	name := p.ContentType
	if p.Filename != "" {
		name += fmt.Sprintf(" %q", p.Filename)
	}
	t.printf("%s%s %s\n", indent, name, t.style(ansiDim, fmt.Sprintf("(%d bytes)", p.Size)))
	for _, c := range p.Parts {
		t.mimeTree(c, indent+"  ")
	}
}
