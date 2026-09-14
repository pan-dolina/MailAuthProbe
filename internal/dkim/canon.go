package dkim

import (
	"bytes"
	"io"
)

// normalizeEOL converts bare LF line endings to CRLF. Messages stored on
// disk frequently use LF; the signer saw CRLF on the wire.
func normalizeEOL(b []byte) []byte {
	if !bytes.Contains(b, []byte("\n")) {
		return b
	}
	out := make([]byte, 0, len(b)+bytes.Count(b, []byte("\n")))
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}

func isWSP(c byte) bool { return c == ' ' || c == '\t' }

// CanonicalHeader returns the canonical form of a raw header field. It is
// exported for signing test fixtures.
func CanonicalHeader(raw []byte, alg string) []byte { return canonHeader(raw, alg) }

// CanonicalBody writes the canonical body to w (see canonBody). It is
// exported for signing test fixtures.
func CanonicalBody(w io.Writer, body []byte, alg string, limit int64) int64 {
	return canonBody(w, normalizeEOL(body), alg, limit)
}

// canonHeader canonicalizes one raw header field (name, colon, value and
// terminating line break) per RFC 6376 section 3.4.1 and 3.4.2.
func canonHeader(raw []byte, alg string) []byte {
	raw = normalizeEOL(raw)
	if alg == CanonSimple {
		if !bytes.HasSuffix(raw, []byte("\r\n")) {
			raw = append(raw[:len(raw):len(raw)], '\r', '\n')
		}
		return raw
	}
	colon := bytes.IndexByte(raw, ':')
	if colon < 0 {
		return nil
	}
	name := bytes.ToLower(bytes.TrimRight(raw[:colon], " \t"))
	value := raw[colon+1:]

	out := make([]byte, 0, len(raw))
	out = append(out, name...)
	out = append(out, ':')
	inWSP := false
	started := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '\r' || c == '\n':
			// Unfold.
		case isWSP(c):
			inWSP = true
		default:
			if inWSP && started {
				out = append(out, ' ')
			}
			inWSP = false
			started = true
			out = append(out, c)
		}
	}
	return append(out, '\r', '\n')
}

// bodyWriter counts the canonical body and forwards at most limit bytes
// (all bytes when limit < 0) to w, implementing the l= tag.
type bodyWriter struct {
	w     io.Writer
	limit int64
	total int64
}

func (b *bodyWriter) write(p []byte) {
	if b.limit < 0 {
		_, _ = b.w.Write(p)
	} else if remaining := b.limit - b.total; remaining > 0 {
		_, _ = b.w.Write(p[:min(int64(len(p)), remaining)])
	}
	b.total += int64(len(p))
}

// canonBody writes the canonicalized body (RFC 6376 sections 3.4.3 and
// 3.4.4) to w, truncated to limit bytes when limit >= 0, and returns the
// length of the complete canonical body.
func canonBody(w io.Writer, body []byte, alg string, limit int64) int64 {
	out := &bodyWriter{w: w, limit: limit}
	relaxed := alg == CanonRelaxed
	var pendingEmpty int
	var buf []byte
	for len(body) > 0 {
		var line []byte
		if i := bytes.IndexByte(body, '\n'); i < 0 {
			line, body = body, nil
		} else {
			line, body = body[:i], body[i+1:]
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if relaxed {
			buf = buf[:0]
			inWSP := false
			for _, ch := range line {
				if isWSP(ch) {
					inWSP = true
					continue
				}
				if inWSP {
					buf = append(buf, ' ')
					inWSP = false
				}
				buf = append(buf, ch)
			}
			line = buf
		}
		// Empty lines are held back: trailing empty lines are removed.
		if len(line) == 0 {
			pendingEmpty++
			continue
		}
		for ; pendingEmpty > 0; pendingEmpty-- {
			out.write([]byte("\r\n"))
		}
		out.write(line)
		out.write([]byte("\r\n"))
	}
	if out.total == 0 && !relaxed {
		// An empty body is a single CRLF under "simple" and empty under
		// "relaxed".
		out.write([]byte("\r\n"))
	}
	return out.total
}

// stripSignatureValue returns the raw DKIM-Signature header with the value
// of the b= tag removed (RFC 6376 section 3.7).
func stripSignatureValue(raw []byte) []byte {
	colon := bytes.IndexByte(raw, ':')
	if colon < 0 {
		return raw
	}
	out := make([]byte, 0, len(raw))
	out = append(out, raw[:colon+1]...)
	rest := raw[colon+1:]
	for len(rest) > 0 {
		end := bytes.IndexByte(rest, ';')
		seg := rest
		if end >= 0 {
			seg = rest[:end+1]
		}
		eq := bytes.IndexByte(seg, '=')
		if eq >= 0 && string(bytes.Trim(seg[:eq], " \t\r\n")) == "b" {
			out = append(out, seg[:eq+1]...)
			if end >= 0 {
				out = append(out, ';')
			} else if bytes.HasSuffix(seg, []byte("\n")) {
				// Keep the header's line terminator.
				trail := len(seg) - 1
				if trail > 0 && seg[trail-1] == '\r' {
					trail--
				}
				out = append(out, seg[trail:]...)
			}
		} else {
			out = append(out, seg...)
		}
		if end < 0 {
			break
		}
		rest = rest[end+1:]
	}
	return out
}
