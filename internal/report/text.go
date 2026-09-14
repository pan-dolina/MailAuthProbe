package report

import (
	"fmt"
	"io"
	"strings"
	"time"

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

func (t *textWriter) printf(format string, args ...any) {
	if t.err != nil {
		return
	}
	_, t.err = fmt.Fprintf(t.w, format, args...)
}

func (t *textWriter) style(code, s string) string {
	if !t.opts.Color || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (t *textWriter) heading(s string) {
	t.printf("\n%s\n", t.style(ansiBold, s))
}

func (t *textWriter) kv(key, value string) {
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

func (t *textWriter) severity(s findings.Severity) string {
	label := fmt.Sprintf("%-8s", strings.ToUpper(s.String()))
	return t.style(severityColors[s], label)
}

func (t *textWriter) result(r string) string {
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
	return r
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
		label := fmt.Sprintf("%d %s", n, s)
		if n > 0 {
			label = t.style(severityColors[s], label)
		}
		parts = append(parts, label)
	}
	t.printf("  %s\n", strings.Join(parts, ", "))
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
				prefix := "  "
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
			line := fmt.Sprintf("  %s  %-32s %s", pref, h.Name, strings.Join(addrs, ", "))
			if h.CNAME != "" {
				line += t.style(ansiYellow, " (CNAME → "+h.CNAME+")")
			}
			if h.Error != "" {
				line += t.style(ansiRed, " ("+h.Error+")")
			}
			t.printf("%s\n", strings.TrimRight(line, " "))
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
	info := fmt.Sprintf("%d lookup(s)", n.Lookups)
	if n.TotalLookups != n.Lookups {
		info += fmt.Sprintf(", %d with includes", n.TotalLookups)
	}
	switch {
	case n.Loop:
		info = t.style(ansiRed, "loop")
	case n.Dynamic:
		info = t.style(ansiDim, "depends on message data")
	case n.Error != "":
		info += ", " + t.style(ansiRed, n.Error)
	}
	branch := ""
	if prefix != "" || n.Via != "" {
		branch = "├─ "
		if last {
			branch = "└─ "
		}
	}
	t.printf("%s%s%s%s %s\n", indent, prefix, branch, label, t.style(ansiDim, "("+info+")"))
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
	t.kv("From", first(h.From))
	t.kv("Sender", first(h.Sender))
	t.kv("Reply-To", first(h.ReplyTo))
	t.kv("Return-Path", first(h.ReturnPath))
	t.kv("To", first(h.To))
	t.kv("Subject", first(h.Subject))
	t.kv("Date", first(h.Date))
	t.kv("Message-ID", first(h.MessageID))
	if m.MIME != nil && t.opts.Verbose {
		t.kv("Content-Type", m.MIME.ContentType)
	}

	t.heading("Verdicts")
	spfRes := "not evaluated"
	if m.SPF != nil && m.SPF.Result != "" {
		spfRes = t.result(string(m.SPF.Result)) + " (" + m.SPF.Domain + ")"
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
		dkimRes = fmt.Sprintf("%s (%d of %d signatures valid)", t.result(res), passing, len(m.DKIM))
	}
	t.kv("DKIM", dkimRes)
	if m.DMARC != nil {
		d := t.result(m.DMARC.Result)
		if m.DMARC.FromDomain != "" {
			d += " (" + m.DMARC.FromDomain
			if m.DMARC.Policy != "" {
				d += ", policy " + string(m.DMARC.Policy)
			}
			d += ")"
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
			t.kv(x.name, x.in.Value+t.style(ansiDim, " ("+src+")"))
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
				rs = append(rs, r.Method+"="+t.result(r.Result))
			}
			id := p.Header.AuthServID
			if id == "" {
				id = "(no authserv-id)"
			}
			t.printf("  #%d %s: %s\n", p.Index, id, strings.Join(rs, " "))
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
