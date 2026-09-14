// Package dnstest provides deterministic DNS data for tests: an in-memory
// Zone that implements dnsresolver.Resolver, and a Server that serves the
// same zone over UDP and TCP on localhost.
//
// Zones are written in a small line-oriented format:
//
//	; comments start with ';' or '#'
//	example.test.            MX    10 mx1.example.test.
//	example.test.            TXT   "v=spf1 ip4:192.0.2.0/24" " -all"
//	mx1.example.test.        A     192.0.2.10
//	www.example.test.        CNAME example.test.
//	192.0.2.10               PTR   mx1.example.test.
//	slow.example.test.       TIMEOUT
//	broken.example.test.     SERVFAIL TXT
//
// Supported record types are A, AAAA, MX, TXT, CNAME and PTR. The pseudo
// types TIMEOUT, SERVFAIL, REFUSED, MALFORMED and TRUNCATE inject failures for
// all query types at a name, or only for the type given after them.
package dnstest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
)

// Behavior is an injected failure mode.
type Behavior string

// Failure modes.
const (
	Timeout   Behavior = "TIMEOUT"
	ServFail  Behavior = "SERVFAIL"
	Refused   Behavior = "REFUSED"
	Malformed Behavior = "MALFORMED"
	Truncate  Behavior = "TRUNCATE"
)

// Record is a single resource record.
type Record struct {
	Name   string // canonical FQDN with trailing dot
	Type   string // A, AAAA, MX, TXT, CNAME, PTR
	Addr   netip.Addr
	Pref   uint16
	Target string // MX, CNAME and PTR target (FQDN)
	Text   string // TXT payload (concatenated)
}

type behaviorRule struct {
	behavior Behavior
	qtype    string // empty: all types
}

// Zone is an in-memory authoritative view used as a resolver in tests. It is
// safe for concurrent use.
type Zone struct {
	mu        sync.Mutex
	records   map[string][]Record
	behaviors map[string][]behaviorRule
	queries   []string
}

var _ dnsresolver.Resolver = (*Zone)(nil)

// NewZone returns an empty zone.
func NewZone() *Zone {
	return &Zone{records: map[string][]Record{}, behaviors: map[string][]behaviorRule{}}
}

// ParseZone parses zone text.
func ParseZone(text string) (*Zone, error) {
	z := NewZone()
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if err := z.AddLine(sc.Text()); err != nil {
			return nil, fmt.Errorf("zone line %d: %w", line, err)
		}
	}
	return z, sc.Err()
}

// MustParseZone is ParseZone that panics on error, for test setup.
func MustParseZone(text string) *Zone {
	z, err := ParseZone(text)
	if err != nil {
		panic(err)
	}
	return z
}

// AddLine adds one line in zone format. Blank and comment lines are ignored.
func (z *Zone) AddLine(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || s[0] == ';' || s[0] == '#' {
		return nil
	}
	owner, rest := cut(s)
	typ, rdata := cut(rest)
	typ = strings.ToUpper(typ)
	if owner == "" || typ == "" {
		return errors.New("expected: <name> <type> [data]")
	}
	name := dnsresolver.Fqdn(owner)
	if a, err := netip.ParseAddr(owner); err == nil {
		name = dnsresolver.ReverseName(a)
	}

	z.mu.Lock()
	defer z.mu.Unlock()
	switch Behavior(typ) {
	case Timeout, ServFail, Refused, Malformed, Truncate:
		z.behaviors[name] = append(z.behaviors[name], behaviorRule{behavior: Behavior(typ), qtype: strings.ToUpper(rdata)})
		return nil
	}

	rec := Record{Name: name, Type: typ}
	switch typ {
	case "A", "AAAA":
		a, err := netip.ParseAddr(rdata)
		if err != nil || (typ == "A") != a.Is4() {
			return fmt.Errorf("invalid %s address %q", typ, rdata)
		}
		rec.Addr = a
	case "MX":
		prefStr, host := cut(rdata)
		pref, err := strconv.ParseUint(prefStr, 10, 16)
		if err != nil || host == "" {
			return fmt.Errorf("invalid MX data %q", rdata)
		}
		rec.Pref = uint16(pref)
		rec.Target = dnsresolver.Fqdn(host)
		if host == "." {
			rec.Target = "."
		}
	case "CNAME", "PTR":
		if rdata == "" {
			return fmt.Errorf("missing %s target", typ)
		}
		rec.Target = dnsresolver.Fqdn(rdata)
	case "TXT":
		text, err := parseTXT(rdata)
		if err != nil {
			return err
		}
		rec.Text = text
	default:
		return fmt.Errorf("unsupported type %q", typ)
	}
	z.records[name] = append(z.records[name], rec)
	return nil
}

func cut(s string) (head, tail string) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i+1:])
}

// parseTXT accepts one or more quoted character-strings (concatenated) or, if
// the data does not start with a quote, the raw remainder of the line.
func parseTXT(s string) (string, error) {
	if !strings.HasPrefix(s, `"`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ', '\t':
			i++
			continue
		case '"':
		default:
			return "", fmt.Errorf("unexpected %q outside quotes in TXT data", s[i])
		}
		i++
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
					n, _ := strconv.Atoi(s[i+1 : i+4])
					if n > 255 {
						return "", fmt.Errorf("invalid escape \\%s", s[i+1:i+4])
					}
					b.WriteByte(byte(n))
					i += 4
					continue
				}
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			if c == '"' {
				closed = true
				i++
				break
			}
			b.WriteByte(c)
			i++
		}
		if !closed {
			return "", errors.New("unterminated quoted string in TXT data")
		}
	}
	return b.String(), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Queries returns the queries received so far as "TYPE name" strings, in
// order. Names are canonical FQDNs.
func (z *Zone) Queries() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return slices.Clone(z.queries)
}

// ResetQueries clears the query log.
func (z *Zone) ResetQueries() {
	z.mu.Lock()
	z.queries = nil
	z.mu.Unlock()
}

// resolution is the outcome of resolving a query against the zone.
type resolution struct {
	behavior Behavior
	nxdomain bool
	chain    []Record // CNAME records followed, in order
	answers  []Record
}

const maxChain = 8

func (z *Zone) resolve(name, qtype string) resolution {
	name = dnsresolver.Fqdn(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.queries = append(z.queries, qtype+" "+name)

	var res resolution
	for range maxChain {
		for _, b := range z.behaviors[name] {
			if b.qtype == "" || b.qtype == qtype {
				res.behavior = b.behavior
				if b.behavior != Truncate {
					return res
				}
			}
		}
		recs := z.records[name]
		if len(recs) == 0 && !z.hasDescendant(name) {
			res.nxdomain = true
			return res
		}
		var cname *Record
		for i := range recs {
			if recs[i].Type == qtype {
				res.answers = append(res.answers, recs[i])
			}
			if recs[i].Type == "CNAME" {
				cname = &recs[i]
			}
		}
		if len(res.answers) > 0 || cname == nil || qtype == "CNAME" {
			return res
		}
		res.chain = append(res.chain, *cname)
		name = cname.Target
	}
	return res
}

// hasDescendant reports whether name is an empty non-terminal, which must be
// answered with NODATA rather than NXDOMAIN (RFC 8020).
func (z *Zone) hasDescendant(name string) bool {
	suffix := "." + name
	for owner := range z.records {
		if strings.HasSuffix(owner, suffix) {
			return true
		}
	}
	return false
}

func (z *Zone) lookup(name, qtype string) ([]Record, error) {
	derr := func(kind dnsresolver.Kind) error {
		return &dnsresolver.Error{Kind: kind, Name: dnsresolver.Trim(name), Type: qtype}
	}
	if !dnsresolver.ValidDomain(name) {
		return nil, derr(dnsresolver.KindInvalidName)
	}
	res := z.resolve(name, qtype)
	switch res.behavior {
	case Timeout, ServFail:
		return nil, derr(dnsresolver.KindTemporary)
	case Refused:
		return nil, derr(dnsresolver.KindRefused)
	case Malformed:
		return nil, derr(dnsresolver.KindMalformed)
	}
	if res.nxdomain {
		return nil, derr(dnsresolver.KindNXDomain)
	}
	return res.answers, nil
}

// LookupTXT implements dnsresolver.Resolver.
func (z *Zone) LookupTXT(_ context.Context, name string) ([]string, error) {
	recs, err := z.lookup(name, "TXT")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, r := range recs {
		out = append(out, r.Text)
	}
	return out, nil
}

// LookupMX implements dnsresolver.Resolver.
func (z *Zone) LookupMX(_ context.Context, name string) ([]dnsresolver.MX, error) {
	recs, err := z.lookup(name, "MX")
	if err != nil {
		return nil, err
	}
	out := []dnsresolver.MX{}
	for _, r := range recs {
		out = append(out, dnsresolver.MX{Host: dnsresolver.Trim(r.Target), Preference: r.Pref})
	}
	return out, nil
}

func (z *Zone) lookupAddr(name, qtype string) ([]netip.Addr, error) {
	recs, err := z.lookup(name, qtype)
	if err != nil {
		return nil, err
	}
	out := []netip.Addr{}
	for _, r := range recs {
		out = append(out, r.Addr)
	}
	return out, nil
}

// LookupA implements dnsresolver.Resolver.
func (z *Zone) LookupA(_ context.Context, name string) ([]netip.Addr, error) {
	return z.lookupAddr(name, "A")
}

// LookupAAAA implements dnsresolver.Resolver.
func (z *Zone) LookupAAAA(_ context.Context, name string) ([]netip.Addr, error) {
	return z.lookupAddr(name, "AAAA")
}

// LookupCNAME implements dnsresolver.Resolver.
func (z *Zone) LookupCNAME(_ context.Context, name string) (string, error) {
	recs, err := z.lookup(name, "CNAME")
	if err != nil {
		return "", err
	}
	if len(recs) == 0 {
		return "", nil
	}
	return dnsresolver.Trim(recs[0].Target), nil
}

// LookupPTR implements dnsresolver.Resolver.
func (z *Zone) LookupPTR(_ context.Context, addr netip.Addr) ([]string, error) {
	recs, err := z.lookup(dnsresolver.ReverseName(addr), "PTR")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, r := range recs {
		out = append(out, dnsresolver.Trim(r.Target))
	}
	return out, nil
}
