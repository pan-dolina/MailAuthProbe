package spf

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// macroContext holds the values available to macro expansion.
type macroContext struct {
	ip       netip.Addr
	sender   string // full MAIL FROM (or postmaster@HELO)
	domain   string // current <domain>
	helo     string
	receiver string
	now      time.Time
	// ptr resolves the validated domain name for the "p" macro.
	ptr func() string
}

// expand performs macro expansion (RFC 7208 section 7.3).
func (m macroString) expand(mc *macroContext) string {
	var b strings.Builder
	for _, tok := range m {
		if tok.letter == 0 {
			b.WriteString(tok.literal)
			continue
		}
		v := transform(mc.value(tok.letter), tok)
		if tok.urlEscape {
			v = urlEscape(v)
		}
		b.WriteString(v)
	}
	return b.String()
}

func (mc *macroContext) value(letter byte) string {
	local, domain := splitSender(mc.sender)
	switch letter {
	case 's':
		return mc.sender
	case 'l':
		return local
	case 'o':
		return domain
	case 'd':
		return mc.domain
	case 'i':
		return dottedIP(mc.ip)
	case 'p':
		if mc.ptr == nil {
			return "unknown"
		}
		return mc.ptr()
	case 'v':
		if mc.ip.Unmap().Is4() {
			return "in-addr"
		}
		return "ip6"
	case 'h':
		return mc.helo
	case 'c':
		return mc.ip.Unmap().String()
	case 'r':
		if mc.receiver == "" {
			return "unknown"
		}
		return mc.receiver
	case 't':
		return strconv.FormatInt(mc.now.Unix(), 10)
	}
	return ""
}

// splitSender splits a MAIL FROM into local part and domain. An empty local
// part becomes "postmaster" (RFC 7208 section 4.3).
func splitSender(sender string) (local, domain string) {
	i := strings.LastIndexByte(sender, '@')
	if i < 0 {
		return "postmaster", sender
	}
	local, domain = sender[:i], sender[i+1:]
	if local == "" {
		local = "postmaster"
	}
	return local, domain
}

// dottedIP formats an IPv4 address in dotted quad and an IPv6 address as
// dot-separated nibbles (RFC 7208 section 7.3).
func dottedIP(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	const hexDigits = "0123456789abcdef"
	a := ip.As16()
	parts := make([]string, 0, 32)
	for _, b := range a {
		parts = append(parts, string(hexDigits[b>>4]), string(hexDigits[b&0xf]))
	}
	return strings.Join(parts, ".")
}

func transform(v string, tok macroToken) string {
	if tok.digits == 0 && !tok.reverse && tok.delims == "" {
		return v
	}
	delims := tok.delims
	if delims == "" {
		delims = "."
	}
	parts := strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune(delims, r) })
	if strings.Trim(v, delims) != v {
		// FieldsFunc drops empty fields; keep them for exact semantics.
		parts = splitAny(v, delims)
	}
	if tok.reverse {
		slices.Reverse(parts)
	}
	if tok.digits > 0 && tok.digits < len(parts) {
		parts = parts[len(parts)-tok.digits:]
	}
	return strings.Join(parts, ".")
}

func splitAny(s, delims string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(delims, s[i]) >= 0 {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// urlEscape escapes characters outside the URI "unreserved" set.
func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlpha(c) || isDigit(c) || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(strconv.FormatUint(uint64(c)|0x100, 16)[1:]))
	}
	return b.String()
}

// truncateDomain applies RFC 7208 section 4.8: if an expanded domain exceeds
// 253 octets, left-hand labels are removed until it fits.
func truncateDomain(d string) string {
	d = strings.TrimSuffix(d, ".")
	for len(d) > 253 {
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return ""
		}
		d = d[i+1:]
	}
	return d
}

// expandDomain expands a term's domain-spec, defaulting to the current
// domain when the term has none.
func (t Term) expandDomain(mc *macroContext) string {
	if t.Domain == "" {
		return mc.domain
	}
	return truncateDomain(t.macro.expand(mc))
}

// ptrValidated implements the PTR validation procedure shared by the "ptr"
// mechanism and the "p" macro (RFC 7208 section 5.5). It returns the
// validated names, at most maxNames PTR records being considered.
func ptrValidated(ctx context.Context, c *evaluator, ip netip.Addr, maxNames int) ([]string, error) {
	names, err := c.resolver.LookupPTR(ctx, ip)
	if err != nil {
		return nil, err
	}
	if len(names) > maxNames {
		names = names[:maxNames]
	}
	var out []string
	for _, n := range names {
		addrs, err := c.lookupAddrs(ctx, n, ip)
		if err != nil {
			continue // lookup errors for individual names are ignored
		}
		if slices.Contains(addrs, ip.Unmap()) {
			out = append(out, strings.ToLower(n))
		}
	}
	return out, nil
}
