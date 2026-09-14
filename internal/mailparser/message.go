// Package mailparser parses RFC 5322 messages and their MIME structure.
//
// The parser is designed for hostile input. It keeps the exact bytes of
// every header field (DKIM signs those bytes), records deviations from the
// standards as defects instead of failing, never decodes attachments and
// never interprets content.
package mailparser

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Header is one header field.
type Header struct {
	// Name as it appears in the message.
	Name string `json:"name"`
	// Value is the unfolded field body with surrounding whitespace removed.
	Value string `json:"value"`
	// Raw holds the exact bytes of the field, including the name, folding
	// and the terminating line break.
	Raw []byte `json:"-"`
}

// DefectKind classifies a deviation from RFC 5322 or MIME.
type DefectKind string

// Defect kinds.
const (
	DefectMalformedHeaderLine    DefectKind = "malformed-header-line"
	DefectLeadingContinuation    DefectKind = "leading-continuation-line"
	DefectWhitespaceBeforeColon  DefectKind = "whitespace-before-colon"
	DefectLongLine               DefectKind = "line-too-long"
	DefectBareLF                 DefectKind = "bare-lf"
	DefectMixedLineEndings       DefectKind = "mixed-line-endings"
	DefectNULByte                DefectKind = "nul-byte"
	DefectEightBitHeader         DefectKind = "8bit-header"
	DefectNoBodySeparator        DefectKind = "no-body-separator"
	DefectMIMEInvalidContentType DefectKind = "mime-invalid-content-type"
	DefectMIMEMissingBoundary    DefectKind = "mime-missing-boundary"
	DefectMIMEUnterminated       DefectKind = "mime-unterminated-multipart"
	DefectMIMENoParts            DefectKind = "mime-no-parts"
	DefectMIMEBadEncoding        DefectKind = "mime-invalid-transfer-encoding"
	DefectMIMEMissingVersion     DefectKind = "mime-missing-version"
	DefectMIMEDepthExceeded      DefectKind = "mime-depth-exceeded"
	DefectMIMEPartsExceeded      DefectKind = "mime-parts-exceeded"
	DefectMIMESizeExceeded       DefectKind = "mime-size-exceeded"
)

// Defect is a problem found while parsing.
type Defect struct {
	Kind   DefectKind `json:"kind"`
	Detail string     `json:"detail"`
}

// Message is a parsed message.
type Message struct {
	Headers []Header `json:"headers"`
	// Body is the raw body, starting after the empty line that ends the
	// header section.
	Body []byte `json:"-"`
	// HasBody is false when the input contained only a header section.
	HasBody bool `json:"has_body"`
	// BodyAvailable is false when the message was parsed with HeadersOnly:
	// the body, if any, is not the real message body.
	BodyAvailable bool `json:"body_available"`
	// HeaderSize is the size of the header section in bytes.
	HeaderSize int      `json:"header_size"`
	Size       int      `json:"size"`
	Defects    []Defect `json:"defects,omitempty"`
	MIME       *Part    `json:"mime,omitempty"`
}

// Get returns all header fields with the given name (case-insensitive), in
// message order.
func (m *Message) Get(name string) []Header {
	var out []Header
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h)
		}
	}
	return out
}

// First returns the value of the first header field with the given name.
func (m *Message) First(name string) (string, bool) {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

func (m *Message) defect(kind DefectKind, format string, args ...any) {
	m.Defects = append(m.Defects, Defect{Kind: kind, Detail: fmt.Sprintf(format, args...)})
}

// Options control parsing.
type Options struct {
	// HeadersOnly treats the whole input as a header section; used for
	// files that contain just the headers of a message.
	HeadersOnly bool
	// Limits; zero fields take the values from DefaultLimits.
	Limits Limits
}

// Parse reads and parses a message. Reading stops as soon as the input
// exceeds Limits.MaxMessageBytes.
func Parse(r io.Reader, opts Options) (*Message, error) {
	limits := opts.Limits.withDefaults()
	data, err := io.ReadAll(io.LimitReader(r, limits.MaxMessageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}
	return ParseBytes(data, opts)
}

// ParseBytes parses a message held in memory. The returned message
// references data; callers must not modify it afterwards.
func ParseBytes(data []byte, opts Options) (*Message, error) {
	limits := opts.Limits.withDefaults()
	if int64(len(data)) > limits.MaxMessageBytes {
		return nil, &LimitError{Limit: "message size", Max: limits.MaxMessageBytes}
	}
	m := &Message{Headers: []Header{}, Size: len(data)}
	checkLineEndings(m, data)
	if bytes.IndexByte(data, 0) >= 0 {
		m.defect(DefectNULByte, "the message contains NUL bytes")
	}

	offset, err := parseHeaderSection(m, data, limits)
	if err != nil {
		return nil, err
	}
	m.HeaderSize = offset
	if offset < len(data) {
		m.HasBody = true
		m.Body = data[offset:]
	}
	if opts.HeadersOnly {
		return m, nil
	}
	m.BodyAvailable = true
	parseMIME(m, limits)
	return m, nil
}

func checkLineEndings(m *Message, data []byte) {
	crlf := bytes.Count(data, []byte("\r\n"))
	lf := bytes.Count(data, []byte("\n"))
	switch {
	case lf > 0 && crlf == 0:
		m.defect(DefectBareLF, "the message uses LF line endings instead of CRLF")
	case lf > crlf:
		m.defect(DefectMixedLineEndings, "the message mixes CRLF and bare LF line endings (%d of %d lines)", lf-crlf, lf)
	}
}

// nextLine returns the line starting at off, including its terminator, and
// the offset of the following line.
func nextLine(data []byte, off int) ([]byte, int) {
	i := bytes.IndexByte(data[off:], '\n')
	if i < 0 {
		return data[off:], len(data)
	}
	return data[off : off+i+1], off + i + 1
}

func trimEOL(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte("\n"))
	return bytes.TrimSuffix(line, []byte("\r"))
}

// parseHeaderSection parses header fields and returns the offset at which
// the body starts.
func parseHeaderSection(m *Message, data []byte, limits Limits) (int, error) {
	off := 0
	var cur *Header
	var curStart int
	flush := func(end int) {
		if cur == nil {
			return
		}
		cur.Raw = data[curStart:end]
		cur.Value = unfold(cur.Raw[bytes.IndexByte(cur.Raw, ':')+1:])
		m.Headers = append(m.Headers, *cur)
		cur = nil
	}

	for off < len(data) {
		if off > limits.MaxHeaderBytes {
			return 0, &LimitError{Limit: "header section size", Max: int64(limits.MaxHeaderBytes)}
		}
		line, next := nextLine(data, off)
		content := trimEOL(line)
		if len(content) > 998 {
			m.defect(DefectLongLine, "header line of %d octets exceeds the 998 octet limit", len(content))
		}

		if len(content) == 0 {
			flush(off)
			return next, nil
		}
		if content[0] == ' ' || content[0] == '\t' {
			if cur == nil {
				m.defect(DefectLeadingContinuation, "continuation line before the first header field")
			}
			off = next
			continue
		}

		colon := bytes.IndexByte(content, ':')
		name := content
		if colon >= 0 {
			name = content[:colon]
		}
		trimmed := bytes.TrimRight(name, " \t")
		if colon <= 0 || len(trimmed) == 0 || !validFieldName(trimmed) {
			// Not a header field: like most MTAs, treat it as the start of the
			// body.
			flush(off)
			m.defect(DefectMalformedHeaderLine, "line %q is not a valid header field; treating it as the start of the body", truncate(content, 60))
			m.defect(DefectNoBodySeparator, "the header section is not terminated by an empty line")
			return off, nil
		}
		if len(trimmed) != len(name) {
			m.defect(DefectWhitespaceBeforeColon, "header field %q has whitespace before the colon (obsolete syntax)", trimmed)
		}
		flush(off)
		if len(m.Headers) >= limits.MaxHeaders {
			return 0, &LimitError{Limit: "header field count", Max: int64(limits.MaxHeaders)}
		}
		cur = &Header{Name: string(trimmed)}
		curStart = off
		off = next
	}
	if len(data) > limits.MaxHeaderBytes {
		return 0, &LimitError{Limit: "header section size", Max: int64(limits.MaxHeaderBytes)}
	}
	flush(len(data))
	return len(data), nil
}

// validFieldName: printable US-ASCII except ':' (RFC 5322 section 2.2).
func validFieldName(b []byte) bool {
	for _, c := range b {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// unfold removes CRLF/LF that precede whitespace and trims the result.
func unfold(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\r' || c == '\n' {
			continue
		}
		sb.WriteByte(c)
	}
	return strings.Trim(sb.String(), " \t")
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
