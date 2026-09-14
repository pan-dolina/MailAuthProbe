// Package received parses Received trace header fields (RFC 5321 section
// 4.4) and models the transport path of a message.
//
// Received headers are free-form in practice. Every value extracted is
// labelled with its provenance: "stated" when the header names it
// unambiguously (for example an IP address in brackets or an explicit
// helo= parameter) and "inferred" when it depends on a convention that not
// every MTA follows (for example that the word after "from" is the HELO
// name).
package received

import (
	"net/netip"
	"strings"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
)

// Provenance of an extracted value.
const (
	Stated   = "stated"
	Inferred = "inferred"
)

// Field is a value with its provenance.
type Field struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

func stated(v string) *Field   { return &Field{Value: v, Source: Stated} }
func inferred(v string) *Field { return &Field{Value: v, Source: Inferred} }

// TLS describes transport encryption for a hop.
type TLS struct {
	Used    bool   `json:"used"`
	Version string `json:"version,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
	Source  string `json:"source"`
}

// Hop is one parsed Received header.
type Hop struct {
	// Index counts from 1 at the origin (the bottom-most header).
	Index      int        `json:"index"`
	Raw        string     `json:"raw"`
	FromHost   *Field     `json:"from_host,omitempty"`
	HELO       *Field     `json:"helo,omitempty"`
	ReverseDNS *Field     `json:"reverse_dns,omitempty"`
	IP         *Field     `json:"ip,omitempty"`
	By         *Field     `json:"by,omitempty"`
	Via        string     `json:"via,omitempty"`
	Protocol   string     `json:"protocol,omitempty"`
	ID         string     `json:"id,omitempty"`
	For        string     `json:"for,omitempty"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
	TLS        *TLS       `json:"tls,omitempty"`
	// Delay since the previous hop, when both timestamps are known.
	Delay *time.Duration `json:"-"`
	// DelaySeconds mirrors Delay for machine-readable output.
	DelaySeconds *float64 `json:"delay_seconds,omitempty"`
	// Problems lists parse problems for this header.
	Problems []string `json:"problems,omitempty"`
}

// Addr returns the parsed client IP address of the hop, if any.
func (h *Hop) Addr() (netip.Addr, bool) {
	if h.IP == nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(h.IP.Value)
	return a, err == nil
}

// token is a lexical element of a Received header.
type token struct {
	text    string
	comment bool
}

// tokenize splits a Received value into words and (possibly nested)
// comments. Quoted strings are kept as single words.
func tokenize(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '(':
			depth, j := 0, i
			for ; j < len(s); j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == '(' {
					depth++
				} else if s[j] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			end := min(j, len(s))
			out = append(out, token{text: strings.TrimSpace(s[i+1 : end]), comment: true})
			i = end + 1
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			end := min(j+1, len(s))
			out = append(out, token{text: s[i:end]})
			i = end
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\r\n(", rune(s[j])) {
				j++
			}
			out = append(out, token{text: s[i:j]})
			i = j
		}
	}
	return out
}

var clauseKeywords = map[string]bool{"from": true, "by": true, "via": true, "with": true, "id": true, "for": true}

type clause struct {
	name     string
	words    []string
	comments []string
	// wordsBeforeComment counts the words that preceded the first comment,
	// which delimits multi-word values such as "Microsoft SMTP Server".
	wordsBeforeComment int
}

// Parse parses a single Received header value.
func Parse(value string) Hop {
	h := Hop{Raw: value}
	body := value
	if i := strings.LastIndexByte(value, ';'); i >= 0 {
		body = value[:i]
		dateText := strings.TrimSpace(value[i+1:])
		if t, err := mailparser.ParseDate(dateText); err == nil {
			h.Timestamp = &t
		} else {
			h.Problems = append(h.Problems, "unparseable date: "+truncate(dateText, 60))
		}
	} else {
		h.Problems = append(h.Problems, "missing date")
	}

	var clauses []*clause
	var cur *clause
	var allComments []string
	for _, tok := range tokenize(body) {
		if tok.comment {
			allComments = append(allComments, tok.text)
			if cur != nil {
				if len(cur.comments) == 0 {
					cur.wordsBeforeComment = len(cur.words)
				}
				cur.comments = append(cur.comments, tok.text)
			}
			continue
		}
		if kw := strings.ToLower(tok.text); clauseKeywords[kw] && (cur == nil || len(cur.words) > 0 || kw != cur.name) {
			cur = &clause{name: kw}
			clauses = append(clauses, cur)
			continue
		}
		if cur == nil {
			h.Problems = append(h.Problems, "text before the first clause: "+truncate(tok.text, 40))
			cur = &clause{name: "?"}
			clauses = append(clauses, cur)
		}
		cur.words = append(cur.words, tok.text)
	}

	seen := map[string]bool{}
	for _, c := range clauses {
		if seen[c.name] && c.name != "?" {
			// Additional words such as "with ESMTPS id X with cipher" are
			// common; keep the first clause of each kind.
			continue
		}
		seen[c.name] = true
		first := ""
		if len(c.words) > 0 {
			first = strings.Trim(c.words[0], ";,")
		}
		switch c.name {
		case "from":
			parseFrom(&h, first, c.comments)
		case "by":
			if first != "" {
				h.By = stated(strings.ToLower(first))
			}
		case "via":
			h.Via = first
		case "with":
			n := len(c.words)
			if len(c.comments) > 0 {
				n = c.wordsBeforeComment
			}
			h.Protocol = strings.Join(c.words[:n], " ")
		case "id":
			h.ID = first
		case "for":
			h.For = strings.Trim(first, "<>")
		}
	}
	if h.By == nil && len(clauses) > 0 {
		h.Problems = append(h.Problems, "missing by clause")
	}
	if len(clauses) == 0 {
		h.Problems = append(h.Problems, "no recognisable clauses")
	}
	h.TLS = detectTLS(h.Protocol, allComments)
	return h
}

func parseFrom(h *Hop, first string, comments []string) {
	if first == "" {
		h.Problems = append(h.Problems, "empty from clause")
		return
	}
	// The from word may itself be an address literal.
	if ip, ok := addressLiteral(first); ok {
		h.IP = stated(ip.String())
		h.HELO = inferred(first)
	} else {
		h.FromHost = stated(strings.ToLower(strings.TrimSuffix(first, ".")))
	}

	var rdns string
	for _, c := range comments {
		lower := strings.ToLower(c)
		for _, word := range strings.FieldsFunc(c, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' }) {
			wl := strings.ToLower(word)
			switch {
			case strings.HasPrefix(wl, "helo="):
				h.HELO = stated(word[len("helo="):])
			case h.IP == nil:
				if ip, ok := addressLiteral(word); ok {
					h.IP = stated(ip.String())
				} else if ip, err := netip.ParseAddr(strings.Trim(word, "[]")); err == nil {
					// Bare address inside a comment, as written by
					// Microsoft Exchange: "from host (192.0.2.1)".
					h.IP = stated(ip.Unmap().String())
				}
			}
		}
		// qmail style: "(HELO name)" or "(EHLO name)".
		if f := strings.Fields(c); len(f) == 2 && (strings.EqualFold(f[0], "HELO") || strings.EqualFold(f[0], "EHLO")) {
			h.HELO = stated(f[1])
		}
		// Postfix/Sendmail style: "(reverse.name [ip])" or "(unknown [ip])".
		if f := strings.Fields(c); len(f) >= 2 && strings.HasPrefix(f[len(f)-1], "[") && rdns == "" {
			if _, ok := addressLiteral(f[len(f)-1]); ok && !strings.Contains(lower, "helo") {
				rdns = strings.TrimSuffix(strings.ToLower(f[0]), ".")
			}
		}
	}

	if h.HELO != nil && h.HELO.Source == Stated {
		// Exim style: the from word is the verified reverse DNS name.
		if h.FromHost != nil {
			h.ReverseDNS = inferred(h.FromHost.Value)
		}
		return
	}
	if h.FromHost != nil && h.HELO == nil {
		// Postfix and Sendmail write the HELO name after "from".
		h.HELO = inferred(h.FromHost.Value)
	}
	if rdns != "" && rdns != "unknown" {
		h.ReverseDNS = inferred(rdns)
	}
}

// addressLiteral parses "[192.0.2.1]" and "[IPv6:2001:db8::1]".
func addressLiteral(s string) (netip.Addr, bool) {
	s = strings.TrimRight(s, ";,")
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return netip.Addr{}, false
	}
	inner := s[1 : len(s)-1]
	if len(inner) > 5 && strings.EqualFold(inner[:5], "ipv6:") {
		inner = inner[5:]
	}
	ip, err := netip.ParseAddr(inner)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func detectTLS(protocol string, comments []string) *TLS {
	for _, c := range comments {
		lower := strings.ToLower(c)
		idx := strings.Index(lower, "tls")
		if idx < 0 {
			continue
		}
		t := &TLS{Used: true, Source: Stated}
		for _, w := range strings.FieldsFunc(c, func(r rune) bool { return r == ' ' || r == ',' || r == '(' || r == ')' }) {
			wl := strings.ToLower(w)
			switch {
			case strings.HasPrefix(wl, "version="):
				t.Version = w[len("version="):]
			case strings.HasPrefix(wl, "cipher="):
				t.Cipher = w[len("cipher="):]
			case strings.HasPrefix(wl, "tlsv1") || strings.HasPrefix(wl, "tls1"):
				if t.Version == "" {
					t.Version = w
				}
			case strings.HasPrefix(wl, "tls_") || strings.HasPrefix(wl, "ecdhe") || strings.Contains(wl, "-gcm-") || strings.Contains(wl, "_gcm_"):
				if t.Cipher == "" {
					t.Cipher = w
				}
			}
		}
		if t.Version != "" || t.Cipher != "" {
			return t
		}
	}
	// RFC 3848: ESMTPS / ESMTPSA / LMTPS / UTF8SMTPS indicate STARTTLS.
	if f := strings.Fields(protocol); len(f) > 0 {
		p := strings.ToUpper(f[0])
		switch {
		case strings.HasSuffix(p, "SMTPS"), strings.HasSuffix(p, "SMTPSA"), p == "LMTPS", p == "LMTPSA":
			return &TLS{Used: true, Source: Inferred}
		case p == "SMTP", p == "ESMTP", p == "ESMTPA", p == "LMTP", p == "UTF8SMTP", p == "UTF8SMTPA":
			return &TLS{Used: false, Source: Inferred}
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
