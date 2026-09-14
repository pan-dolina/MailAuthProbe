package dkim

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
)

// Canonicalization algorithms.
const (
	CanonSimple  = "simple"
	CanonRelaxed = "relaxed"
)

// Signature is a parsed DKIM-Signature header field.
type Signature struct {
	Header mailparser.Header `json:"-"`

	Version       string   `json:"version"`
	Algorithm     string   `json:"algorithm"`
	KeyAlgorithm  string   `json:"-"`
	HashAlgorithm string   `json:"-"`
	Signature     []byte   `json:"-"`
	SignatureB64  string   `json:"-"`
	BodyHash      []byte   `json:"-"`
	HeaderCanon   string   `json:"header_canonicalization"`
	BodyCanon     string   `json:"body_canonicalization"`
	Domain        string   `json:"domain"`
	SignedHeaders []string `json:"signed_headers"`
	AUID          string   `json:"auid"`
	BodyLength    *int64   `json:"body_length,omitempty"`
	QueryMethods  []string `json:"query_methods,omitempty"`
	Selector      string   `json:"selector"`
	Timestamp     *int64   `json:"timestamp,omitempty"`
	Expiration    *int64   `json:"expiration,omitempty"`
	CopiedHeaders string   `json:"-"`
}

// ShortB returns the first characters of the b= value, as used by the
// header.b property of Authentication-Results (RFC 6008).
func (s *Signature) ShortB(n int) string {
	if len(s.SignatureB64) <= n {
		return s.SignatureB64
	}
	return s.SignatureB64[:n]
}

// ParseSignature parses a DKIM-Signature header field.
func ParseSignature(h mailparser.Header) (*Signature, error) {
	tags, err := parseTagList(h.Value)
	if err != nil {
		return nil, err
	}
	s := &Signature{Header: h, HeaderCanon: CanonSimple, BodyCanon: CanonSimple, QueryMethods: []string{"dns/txt"}}
	values := map[string]string{}
	for _, t := range tags {
		values[t.name] = t.value
	}
	for _, req := range []string{"v", "a", "b", "bh", "d", "h", "s"} {
		if _, ok := values[req]; !ok {
			return nil, fmt.Errorf("required tag %s= is missing", req)
		}
	}

	if s.Version = values["v"]; s.Version != "1" {
		return nil, fmt.Errorf("unsupported version v=%s", s.Version)
	}
	s.Algorithm = strings.ToLower(values["a"])
	key, hash, ok := strings.Cut(s.Algorithm, "-")
	if !ok || key == "" || hash == "" {
		return nil, fmt.Errorf("invalid algorithm a=%s", values["a"])
	}
	s.KeyAlgorithm, s.HashAlgorithm = key, hash

	s.SignatureB64 = stripFWS(values["b"])
	if s.Signature, err = base64.StdEncoding.DecodeString(s.SignatureB64); err != nil || len(s.Signature) == 0 {
		return nil, errors.New("b= is not valid base64")
	}
	if s.BodyHash, err = base64.StdEncoding.DecodeString(stripFWS(values["bh"])); err != nil || len(s.BodyHash) == 0 {
		return nil, errors.New("bh= is not valid base64")
	}

	if c, ok := values["c"]; ok {
		hc, bc, hasBody := strings.Cut(strings.ToLower(c), "/")
		s.HeaderCanon = hc
		if hasBody {
			s.BodyCanon = bc
		}
		for _, v := range []string{s.HeaderCanon, s.BodyCanon} {
			if v != CanonSimple && v != CanonRelaxed {
				return nil, fmt.Errorf("unknown canonicalization c=%s", c)
			}
		}
	}

	s.Domain = strings.ToLower(strings.TrimSuffix(values["d"], "."))
	if s.Domain == "" || !strings.Contains(s.Domain, ".") && len(s.Domain) < 2 {
		return nil, fmt.Errorf("invalid signing domain d=%s", values["d"])
	}
	s.Selector = strings.ToLower(values["s"])
	if s.Selector == "" {
		return nil, errors.New("empty selector s=")
	}

	for _, name := range strings.Split(values["h"], ":") {
		name = strings.Trim(name, " \t\r\n")
		if name == "" {
			return nil, errors.New("h= contains an empty header name")
		}
		s.SignedHeaders = append(s.SignedHeaders, name)
	}
	hasFrom := false
	for _, n := range s.SignedHeaders {
		if strings.EqualFold(n, "from") {
			hasFrom = true
		}
	}
	if !hasFrom {
		return nil, errors.New("h= does not include the From header")
	}

	s.AUID = "@" + s.Domain
	if i, ok := values["i"]; ok {
		at := strings.LastIndexByte(i, '@')
		if at < 0 {
			return nil, fmt.Errorf("invalid identity i=%s", i)
		}
		idDomain := strings.ToLower(strings.TrimSuffix(i[at+1:], "."))
		if idDomain != s.Domain && !strings.HasSuffix(idDomain, "."+s.Domain) {
			return nil, fmt.Errorf("identity i=%s is not in the signing domain %s", i, s.Domain)
		}
		s.AUID = i
	}
	if l, ok := values["l"]; ok {
		n, err := strconv.ParseInt(l, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid body length l=%s", l)
		}
		s.BodyLength = &n
	}
	if q, ok := values["q"]; ok {
		s.QueryMethods = splitList(strings.ToLower(q))
		if !containsFold(s.QueryMethods, "dns/txt") {
			return nil, fmt.Errorf("unsupported query method q=%s", q)
		}
	}
	for _, tt := range []struct {
		name string
		dst  **int64
	}{{"t", &s.Timestamp}, {"x", &s.Expiration}} {
		if v, ok := values[tt.name]; ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid %s=%s", tt.name, v)
			}
			*tt.dst = &n
		}
	}
	if s.Timestamp != nil && s.Expiration != nil && *s.Expiration < *s.Timestamp {
		return nil, errors.New("x= is earlier than t=")
	}
	s.CopiedHeaders = values["z"]
	return s, nil
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}
