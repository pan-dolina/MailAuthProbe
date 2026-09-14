package mailparser

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

// Part describes one node of the MIME tree. Content is never decoded.
type Part struct {
	ContentType      string  `json:"content_type"`
	Charset          string  `json:"charset,omitempty"`
	Boundary         string  `json:"boundary,omitempty"`
	Disposition      string  `json:"disposition,omitempty"`
	Filename         string  `json:"filename,omitempty"`
	TransferEncoding string  `json:"transfer_encoding,omitempty"`
	Size             int     `json:"size"`
	Depth            int     `json:"depth"`
	Parts            []*Part `json:"parts,omitempty"`
}

// Attachments returns the parts that carry a filename or an attachment
// disposition.
func (p *Part) Attachments() []*Part {
	var out []*Part
	var walk func(*Part)
	walk = func(p *Part) {
		if p.Filename != "" || p.Disposition == "attachment" {
			out = append(out, p)
		}
		for _, c := range p.Parts {
			walk(c)
		}
	}
	walk(p)
	return out
}

type headerGetter interface {
	Get(key string) string
}

type messageHeaders struct{ m *Message }

func (h messageHeaders) Get(key string) string {
	v, _ := h.m.First(key)
	return v
}

type mimeWalker struct {
	m      *Message
	limits Limits
	parts  int
	// examined counts the bytes copied out of part bodies. Every nesting
	// level copies its content, so without a bound a deeply nested message
	// would be held in memory many times over.
	examined    int
	maxExamined int
	// stopped is set once a MIME limit is hit; the remaining structure is
	// not examined.
	stopped bool
}

func parseMIME(m *Message, limits Limits) {
	if _, ok := m.First("Content-Type"); !ok {
		m.MIME = &Part{ContentType: "text/plain", Charset: "us-ascii", Size: len(m.Body)}
		return
	}
	w := &mimeWalker{m: m, limits: limits, maxExamined: 2*len(m.Body) + 1<<20}
	m.MIME = w.part(messageHeaders{m}, m.Body, 0)
	if _, ok := m.First("MIME-Version"); !ok && strings.HasPrefix(m.MIME.ContentType, "multipart/") {
		m.defect(DefectMIMEMissingVersion, "multipart message without a MIME-Version header")
	}
}

func (w *mimeWalker) part(h headerGetter, body []byte, depth int) *Part {
	w.parts++
	p := &Part{Depth: depth, Size: len(body), ContentType: "text/plain"}

	if ct := h.Get("Content-Type"); ct != "" {
		mediaType, params, err := mime.ParseMediaType(ct)
		if err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter) {
			w.m.defect(DefectMIMEInvalidContentType, "invalid Content-Type %q: %v", truncate([]byte(ct), 80), err)
		} else {
			if err != nil {
				w.m.defect(DefectMIMEInvalidContentType, "Content-Type %q has invalid parameters", truncate([]byte(ct), 80))
			}
			p.ContentType = mediaType
			p.Charset = params["charset"]
			p.Boundary = params["boundary"]
			if name := params["name"]; name != "" {
				p.Filename = name
			}
		}
	}
	if cd := h.Get("Content-Disposition"); cd != "" {
		if disp, params, err := mime.ParseMediaType(cd); err == nil {
			p.Disposition = disp
			if fn := params["filename"]; fn != "" {
				p.Filename = fn
			}
		}
	}
	if cte := strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))); cte != "" {
		p.TransferEncoding = cte
		switch cte {
		case "7bit", "8bit", "binary", "quoted-printable", "base64":
		default:
			w.m.defect(DefectMIMEBadEncoding, "unknown Content-Transfer-Encoding %q", truncate([]byte(cte), 40))
		}
	}

	if !strings.HasPrefix(p.ContentType, "multipart/") {
		return p
	}
	if depth >= w.limits.MaxMIMEDepth {
		if !w.stopped {
			w.m.defect(DefectMIMEDepthExceeded, "multipart nesting deeper than %d levels; inner parts were not examined", w.limits.MaxMIMEDepth)
		}
		w.stopped = true
		return p
	}
	if p.Boundary == "" {
		w.m.defect(DefectMIMEMissingBoundary, "%s part without a boundary parameter", p.ContentType)
		return p
	}
	if !bytes.Contains(body, []byte("--"+p.Boundary)) {
		w.m.defect(DefectMIMENoParts, "boundary %q never appears in the %s body", truncate([]byte(p.Boundary), 40), p.ContentType)
		return p
	}

	mr := multipart.NewReader(bytes.NewReader(body), p.Boundary)
	for !w.stopped {
		if w.parts >= w.limits.MaxMIMEParts {
			w.m.defect(DefectMIMEPartsExceeded, "more than %d MIME parts; remaining parts were not examined", w.limits.MaxMIMEParts)
			w.stopped = true
			break
		}
		child, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			w.m.defect(DefectMIMEUnterminated, "%s body is malformed: %v", p.ContentType, err)
			break
		}
		content, err := io.ReadAll(io.LimitReader(child, int64(w.maxExamined-w.examined)+1))
		w.examined += len(content)
		if w.examined > w.maxExamined {
			w.m.defect(DefectMIMESizeExceeded, "nested MIME parts exceed the analysis budget of %d bytes; remaining parts were not examined", w.maxExamined)
			w.stopped = true
			break
		}
		if err != nil {
			w.m.defect(DefectMIMEUnterminated, "%s body ends before its closing boundary: %v", p.ContentType, err)
			p.Parts = append(p.Parts, w.part(child.Header, content, depth+1))
			break
		}
		p.Parts = append(p.Parts, w.part(child.Header, content, depth+1))
	}
	if len(p.Parts) == 0 && !w.stopped {
		w.m.defect(DefectMIMENoParts, "%s body contains no parts", p.ContentType)
	}
	return p
}
