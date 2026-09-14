package spf

import (
	"errors"
	"fmt"
	"strings"
)

// macroToken is a literal run or a macro-expand.
type macroToken struct {
	literal string

	letter    byte // lower-case macro letter; 0 for literals
	urlEscape bool // upper-case letter
	digits    int  // number of right-hand parts to keep; 0 = all
	reverse   bool
	delims    string
}

type macroString []macroToken

func (m macroString) hasMacros() bool {
	for _, t := range m {
		if t.letter != 0 {
			return true
		}
	}
	return false
}

// parseMacroString parses a macro-string (RFC 7208 section 7.1). The letters
// c, r and t are only allowed when expExpansion is true.
func parseMacroString(s string, expExpansion bool) (macroString, error) {
	var out macroString
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, macroToken{literal: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			// macro-literal = %x21-24 / %x26-7E (visible characters except %)
			if c < 0x21 || c > 0x7e {
				return nil, fmt.Errorf("invalid character 0x%02x in macro-string", c)
			}
			lit.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return nil, errors.New(`dangling "%" in macro-string`)
		}
		i++
		switch s[i] {
		case '%':
			lit.WriteByte('%')
		case '_':
			lit.WriteByte(' ')
		case '-':
			lit.WriteString("%20")
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, errors.New(`unterminated "%{" in macro-string`)
			}
			tok, err := parseMacroExpand(s[i+1:i+end], expExpansion)
			if err != nil {
				return nil, err
			}
			flush()
			out = append(out, tok)
			i += end
		default:
			return nil, fmt.Errorf(`invalid macro escape "%%%c"`, s[i])
		}
	}
	flush()
	return out, nil
}

func parseMacroExpand(body string, expExpansion bool) (macroToken, error) {
	if body == "" {
		return macroToken{}, errors.New(`empty macro "%{}"`)
	}
	c := body[0]
	tok := macroToken{letter: c | 0x20, urlEscape: c >= 'A' && c <= 'Z'}
	switch tok.letter {
	case 's', 'l', 'o', 'd', 'i', 'p', 'h', 'v':
	case 'c', 'r', 't':
		if !expExpansion {
			return macroToken{}, fmt.Errorf(`macro letter %q is only allowed in "exp" explanations`, c)
		}
	default:
		return macroToken{}, fmt.Errorf("unknown macro letter %q", c)
	}
	rest := body[1:]
	i := 0
	for i < len(rest) && isDigit(rest[i]) {
		i++
	}
	if i > 0 {
		n := 0
		for _, d := range rest[:i] {
			n = n*10 + int(d-'0')
			if n > 1000 {
				break
			}
		}
		if n == 0 {
			return macroToken{}, errors.New("macro transformer digit count must be non-zero")
		}
		tok.digits = n
	}
	rest = rest[i:]
	if rest != "" && (rest[0] == 'r' || rest[0] == 'R') {
		tok.reverse = true
		rest = rest[1:]
	}
	for j := 0; j < len(rest); j++ {
		if !strings.ContainsRune(".-+,/_=", rune(rest[j])) {
			return macroToken{}, fmt.Errorf("invalid macro delimiter %q", rest[j])
		}
	}
	tok.delims = rest
	return tok, nil
}

// validDomainEnd checks the domain-end production:
//
//	domain-end = ( "." toplabel [ "." ] ) / macro-expand
//
// A domain-spec ending in a macro cannot be validated before expansion.
func (m macroString) validDomainEnd() bool {
	if len(m) == 0 {
		return false
	}
	last := m[len(m)-1]
	if last.letter != 0 {
		return true
	}
	s := strings.TrimSuffix(last.literal, ".")
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		// A single label such as "localhost", or a label glued to a macro
		// such as "%{d}com", does not match domain-end.
		return false
	}
	if strings.HasSuffix(s[:i], ".") {
		return false // empty label
	}
	return validTopLabel(s[i+1:])
}

// validTopLabel: ( *alphanum ALPHA *alphanum ) /
// ( 1*alphanum "-" *( alphanum / "-" ) alphanum ).
func validTopLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	hasAlpha, hasHyphen := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlpha(c):
			hasAlpha = true
		case isDigit(c):
		case c == '-':
			hasHyphen = true
		default:
			return false
		}
	}
	if hasHyphen {
		return s[0] != '-' && s[len(s)-1] != '-'
	}
	return hasAlpha
}
