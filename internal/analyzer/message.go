package analyzer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/arc"
	"github.com/marcindolinski/mailauthprobe/internal/authres"
	"github.com/marcindolinski/mailauthprobe/internal/dkim"
	"github.com/marcindolinski/mailauthprobe/internal/dmarc"
	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/findings"
	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
	"github.com/marcindolinski/mailauthprobe/internal/received"
	"github.com/marcindolinski/mailauthprobe/internal/report"
	"github.com/marcindolinski/mailauthprobe/internal/spf"
)

// InputError wraps failures to read or parse the input message.
type InputError struct{ Err error }

func (e *InputError) Error() string { return e.Err.Error() }
func (e *InputError) Unwrap() error { return e.Err }

// Message analyses a complete message read from r. With headersOnly the
// input is treated as a header section and body hashes are not checked.
// target names the input in the report (a file name or "-").
func Message(ctx context.Context, r io.Reader, target string, headersOnly bool, opts Options) (*report.Report, error) {
	kind := report.KindMessage
	if headersOnly {
		kind = report.KindHeaders
	}
	s := newSession(opts, kind, target)
	msg, err := mailparser.Parse(r, mailparser.Options{HeadersOnly: headersOnly, Limits: opts.Limits})
	if err != nil {
		s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorInput, Component: "message", Message: err.Error()})
		return s.finish(ctx), &InputError{Err: err}
	}
	if len(msg.Headers) == 0 {
		err := errors.New("input contains no header fields")
		s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorInput, Component: "message", Message: err.Error()})
		return s.finish(ctx), &InputError{Err: err}
	}
	s.analyzeMessage(ctx, msg)
	return s.finish(ctx), nil
}

func values(msg *mailparser.Message, name string) []string {
	var out []string
	for _, h := range msg.Get(name) {
		out = append(out, h.Value)
	}
	return out
}

func (s *session) analyzeMessage(ctx context.Context, msg *mailparser.Message) {
	m := &report.Message{
		Size:          msg.Size,
		HeaderSize:    msg.HeaderSize,
		BodyAvailable: msg.BodyAvailable,
		MIME:          msg.MIME,
		Defects:       msg.Defects,
		Headers: report.MessageHeaders{
			From:        values(msg, "From"),
			Sender:      values(msg, "Sender"),
			ReplyTo:     values(msg, "Reply-To"),
			ReturnPath:  values(msg, "Return-Path"),
			To:          values(msg, "To"),
			Subject:     values(msg, "Subject"),
			MessageID:   values(msg, "Message-ID"),
			Date:        values(msg, "Date"),
			MIMEVersion: values(msg, "MIME-Version"),
			ContentType: values(msg, "Content-Type"),
		},
		DKIM:        []dkim.Verification{},
		AuthResults: []authres.Parsed{},
	}
	s.rep.Message = m
	s.structureFindings(msg, m)

	// Transport path.
	m.Received = received.Build(values(msg, "Received"))
	s.add(m.Received.Findings...)
	for _, v := range values(msg, "Received-SPF") {
		if rs, err := authres.ParseReceivedSPF(v); err == nil {
			m.ReceivedSPF = append(m.ReceivedSPF, *rs)
		}
	}

	// DKIM.
	m.DKIM = dkim.VerifyMessage(ctx, s.resolver, msg, dkim.VerifyOptions{Now: s.opts.Now})
	s.dkimFindings(msg, m)

	// SPF.
	inputs := s.spfInputs(msg, m)
	checker := &spf.Checker{Resolver: s.resolver}
	m.SPF = checker.CheckMessage(ctx, inputs)
	s.add(m.SPF.Findings...)
	for _, ev := range []*spf.Evaluation{m.SPF.MailFrom, m.SPF.HELO} {
		if ev != nil && ev.Result == spf.ResultTempError {
			s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorDNS, Component: "spf", Message: ev.Reason})
		}
	}

	// DMARC.
	din := dmarc.MessageInput{FromHeaders: m.Headers.From, SPFResult: string(m.SPF.Result), SPFDomain: m.SPF.Domain}
	for _, v := range m.DKIM {
		din.DKIM = append(din.DKIM, dmarc.DKIMInput{Domain: v.Domain, Result: string(v.Result)})
	}
	m.DMARC = dmarc.EvaluateMessage(ctx, s.resolver, din)
	s.add(m.DMARC.Findings...)
	if m.DMARC.Result == dmarc.MessageTempError {
		s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorDNS, Component: "dmarc", Message: m.DMARC.Reason})
	}

	// ARC and Authentication-Results.
	if m.ARC = arc.Summarize(msg); m.ARC != nil {
		s.add(m.ARC.Findings...)
	}
	m.AuthResults = authres.ParseAll(values(msg, "Authentication-Results"))
	computed := authres.Computed{
		SPF:         string(m.SPF.Result),
		SPFInferred: inputs.IP != nil && inputs.IP.Inferred,
		DMARC:       m.DMARC.Result,
	}
	if !msg.BodyAvailable {
		computed.DKIM = nil // header-only verification cannot confirm DKIM results
	} else {
		for _, v := range m.DKIM {
			computed.DKIM = append(computed.DKIM, authres.ComputedDKIM{Domain: v.Domain, Selector: v.Selector, HeaderB: v.HeaderB, Result: string(v.Result)})
		}
	}
	if m.DMARC.Result == dmarc.MessagePermError {
		computed.DMARC = ""
	}
	s.add(authres.Compare(m.AuthResults, computed)...)
}

// spfInputs combines operator-supplied values with values inferred from
// headers. Operator values always win.
func (s *session) spfInputs(msg *mailparser.Message, m *report.Message) spf.MessageInputs {
	var in spf.MessageInputs
	flag := func(v string) *spf.Input { return &spf.Input{Value: v, Source: spf.SourceFlag} }
	if s.opts.SourceIP != "" {
		in.IP = flag(s.opts.SourceIP)
	}
	if s.opts.HELO != "" {
		in.HELO = flag(s.opts.HELO)
	}
	if s.opts.MailFrom != "" {
		if s.opts.MailFrom == "<>" {
			in.NullSender = true
		} else {
			in.MailFrom = flag(strings.Trim(s.opts.MailFrom, "<>"))
		}
	}

	// Received-SPF written by the receiving MTA carries all three values.
	if len(m.ReceivedSPF) > 0 {
		rs := m.ReceivedSPF[0]
		inferred := func(v string) *spf.Input { return &spf.Input{Value: v, Source: spf.SourceReceivedSPF, Inferred: true} }
		if in.IP == nil {
			if ip, err := netip.ParseAddr(rs.Params["client-ip"]); err == nil {
				in.IP = inferred(ip.String())
			}
		}
		if in.HELO == nil && rs.Params["helo"] != "" {
			in.HELO = inferred(rs.Params["helo"])
		}
		if in.MailFrom == nil && !in.NullSender && strings.Contains(rs.Params["envelope-from"], "@") {
			in.MailFrom = inferred(strings.Trim(rs.Params["envelope-from"], "<>"))
		}
	}
	if in.IP == nil || in.HELO == nil {
		if src, ok := m.Received.InferSource(); ok {
			if in.IP == nil {
				in.IP = &spf.Input{Value: src.IP, Source: spf.SourceReceived, Inferred: true}
			}
			if in.HELO == nil && src.HELO != "" && dnsresolver.ValidDomain(src.HELO) {
				in.HELO = &spf.Input{Value: src.HELO, Source: spf.SourceReceived, Inferred: true}
			}
		}
	}
	if in.MailFrom == nil && !in.NullSender && len(m.Headers.ReturnPath) > 0 {
		addr, err := mailparser.ParseReturnPath(m.Headers.ReturnPath[0])
		switch {
		case errors.Is(err, mailparser.ErrNullReversePath):
			in.NullSender = true
		case err == nil:
			in.MailFrom = &spf.Input{Value: addr, Source: spf.SourceReturnPath, Inferred: true}
		}
	}
	return in
}

func (s *session) dkimFindings(msg *mailparser.Message, m *report.Message) {
	sigCount := len(msg.Get("DKIM-Signature"))
	if sigCount == 0 {
		s.add(findings.DKIMUnsigned.New("", "The message has no DKIM-Signature. Its content and From domain are not cryptographically authenticated."))
		return
	}
	if sigCount > dkim.MaxSignatures {
		s.add(findings.DKIMTooManySignatures.New("", fmt.Sprintf("The message has %d DKIM signatures; only the first %d were verified.", sigCount, dkim.MaxSignatures)))
	}
	seenKeys := map[string]bool{}
	for _, v := range m.DKIM {
		subject := v.KeyName
		if subject == "" {
			subject = fmt.Sprintf("signature #%d", v.Index)
		}
		ev := []string{fmt.Sprintf("d=%s s=%s a=%s c=%s", v.Domain, v.Selector, v.Algorithm, v.Canonicalization)}
		if len(v.SignedHeaders) > 0 {
			ev = append(ev, "h="+strings.Join(v.SignedHeaders, ":"))
		}
		desc := fmt.Sprintf("DKIM signature #%d: %s.", v.Index, v.Reason)
		switch {
		case v.Result == dkim.ResultPass:
			s.add(findings.DKIMSignatureValid.New(subject, desc, ev...))
		case v.Result == dkim.ResultNeutral && v.SignatureOK != nil && *v.SignatureOK:
			s.add(findings.DKIMHeaderOnlyValid.New(subject, desc, ev...))
		case v.Failure == dkim.FailBodyHash:
			s.add(findings.DKIMBodyHashMismatch.New(subject, desc, ev...))
		case v.Failure == dkim.FailSignature:
			s.add(findings.DKIMSignatureInvalid.New(subject, desc, ev...))
		case v.Failure == dkim.FailInsecureAlgorithm:
			s.add(findings.DKIMInsecureAlgorithm.New(subject, desc, ev...))
		case v.Failure == dkim.FailExpired:
			s.add(findings.DKIMExpired.New(subject, desc, ev...))
		case v.Result == dkim.ResultTempError:
			s.add(findings.DKIMVerifyTempError.New(subject, desc, ev...))
			s.rep.Errors = append(s.rep.Errors, report.Error{Kind: report.ErrorDNS, Component: "dkim", Message: v.Reason})
		default:
			s.add(findings.DKIMVerifyPermError.New(subject, desc, ev...))
		}
		if v.BodyLength != nil {
			s.add(findings.DKIMBodyLength.New(subject, fmt.Sprintf("Signature #%d uses l=%d; content appended after the signed length is not covered by the signature.", v.Index, *v.BodyLength)))
		}
		if len(v.SignedHeaders) > 0 && !containsFold(v.SignedHeaders, "subject") {
			s.add(findings.DKIMUnsignedHeaders.New(subject, fmt.Sprintf("Signature #%d does not cover the Subject header, which can be changed without breaking the signature.", v.Index)))
		}
		if v.Key != nil && !seenKeys[v.KeyName] {
			seenKeys[v.KeyName] = true
			for _, f := range dkim.KeyFindings(v.KeyName, v.Key) {
				if f.ID != findings.DKIMKeyRevoked.ID {
					s.add(f)
				}
			}
		}
	}
	if !msg.BodyAvailable {
		s.add(findings.MsgHeadersOnly.New("", "Only the header section was analysed; DKIM body hashes were not checked."))
	}
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

var riskyExtensions = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".pif": true, ".bat": true, ".cmd": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".hta": true, ".ps1": true, ".msi": true, ".jar": true, ".lnk": true,
	".iso": true, ".img": true, ".vhd": true, ".one": true, ".xlsm": true, ".docm": true, ".html": true, ".htm": true,
	".svg": true, ".zip": true, ".rar": true, ".7z": true,
}

func (s *session) structureFindings(msg *mailparser.Message, m *report.Message) {
	var headerDefects, mimeDefects, lineDefects, badBytes, limitDefects []string
	for _, d := range msg.Defects {
		entry := string(d.Kind) + ": " + d.Detail
		switch d.Kind {
		case mailparser.DefectBareLF, mailparser.DefectMixedLineEndings:
			lineDefects = append(lineDefects, entry)
		case mailparser.DefectNULByte, mailparser.DefectEightBitHeader:
			badBytes = append(badBytes, entry)
		case mailparser.DefectMIMEDepthExceeded, mailparser.DefectMIMEPartsExceeded:
			limitDefects = append(limitDefects, entry)
		case mailparser.DefectMIMEInvalidContentType, mailparser.DefectMIMEMissingBoundary, mailparser.DefectMIMEUnterminated,
			mailparser.DefectMIMENoParts, mailparser.DefectMIMEBadEncoding, mailparser.DefectMIMEMissingVersion:
			mimeDefects = append(mimeDefects, entry)
		default:
			headerDefects = append(headerDefects, entry)
		}
	}
	if len(headerDefects) > 0 {
		s.add(findings.MsgMalformedHeaders.New("", "The header section does not conform to RFC 5322.", headerDefects...))
	}
	if len(mimeDefects) > 0 {
		s.add(findings.MsgMalformedMIME.New("", "The MIME structure is malformed.", mimeDefects...))
	}
	if len(lineDefects) > 0 {
		s.add(findings.MsgLineEndings.New("", "The message does not use CRLF line endings throughout; it was probably saved by a local tool. DKIM verification normalises line endings.", lineDefects...))
	}
	if len(badBytes) > 0 {
		s.add(findings.MsgBadBytes.New("", "The message contains bytes that are not allowed in Internet messages.", badBytes...))
	}
	if len(limitDefects) > 0 {
		s.add(findings.MsgMIMELimit.New("", "Parts of the MIME structure were not analysed.", limitDefects...))
	}

	h := m.Headers
	if len(h.From) == 0 {
		s.add(findings.MsgMissingRequired.New("From", "The message has no From header."))
	}
	if len(h.Date) == 0 {
		s.add(findings.MsgMissingRequired.New("Date", "The message has no Date header."))
	} else if _, err := mailparser.ParseDate(h.Date[0]); err != nil {
		s.add(findings.MsgInvalidDate.New("Date", fmt.Sprintf("The Date header %q cannot be parsed.", h.Date[0])))
	}
	if len(h.MessageID) == 0 {
		s.add(findings.MsgMissingMessageID.New("Message-ID", "The message has no Message-ID header."))
	}
	for name, vals := range map[string][]string{"Date": h.Date, "Sender": h.Sender, "Reply-To": h.ReplyTo, "To": h.To, "Subject": h.Subject, "Message-ID": h.MessageID} {
		if len(vals) > 1 {
			s.add(findings.MsgDuplicateHeader.New(name, fmt.Sprintf("The %s header appears %d times.", name, len(vals)), vals...))
		}
	}
	if len(h.From) > 1 {
		s.add(findings.MsgDuplicateHeader.New("From", fmt.Sprintf("The From header appears %d times.", len(h.From)), h.From...).WithSeverity(findings.SeverityHigh))
	}

	fromDomain := ""
	if len(h.From) == 1 {
		if list, err := mailparser.ParseAddressList(h.From[0]); err == nil && len(list) == 1 {
			fromDomain = list[0].Domain
		}
	}
	if fromDomain != "" {
		compare := func(values []string, rule findings.Rule, label string) {
			if len(values) == 0 {
				return
			}
			list, err := mailparser.ParseAddressList(values[0])
			if err != nil {
				return
			}
			for _, a := range list {
				if a.Domain != "" && dmarc.OrganizationalDomain(a.Domain) != dmarc.OrganizationalDomain(fromDomain) {
					s.add(rule.New(label, fmt.Sprintf("%s address %s belongs to a different organization than the From domain %s.", label, a.Address, fromDomain)))
					return
				}
			}
		}
		compare(h.ReplyTo, findings.MsgReplyToMismatch, "Reply-To")
		compare(h.Sender, findings.MsgSenderMismatch, "Sender")
		if len(h.ReturnPath) > 0 {
			if addr, err := mailparser.ParseReturnPath(h.ReturnPath[0]); err == nil {
				if d := mailparser.DomainOf(addr); dmarc.OrganizationalDomain(d) != dmarc.OrganizationalDomain(fromDomain) {
					s.add(findings.MsgReturnPathMismatch.New("Return-Path", fmt.Sprintf("The envelope sender %s belongs to a different organization than the From domain %s (normal for mailing lists and email service providers).", addr, fromDomain)))
				}
			}
		}
	}

	if msg.MIME != nil {
		var risky []string
		for _, p := range msg.MIME.Attachments() {
			if riskyExtensions[strings.ToLower(path.Ext(p.Filename))] {
				risky = append(risky, fmt.Sprintf("%s (%s, %d bytes)", p.Filename, p.ContentType, p.Size))
			}
		}
		if len(risky) > 0 {
			s.add(findings.MsgRiskyAttachment.New("", "The message carries attachments whose file types are commonly used to deliver malware.", risky...))
		}
	}
}
