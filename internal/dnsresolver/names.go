package dnsresolver

import (
	"net/netip"
	"strings"
)

// Fqdn returns name in canonical form: lower case with a trailing dot.
func Fqdn(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// Trim returns name in lower case without the trailing dot.
func Trim(name string) string {
	if name == "." {
		return name
	}
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// ValidDomain reports whether name is syntactically usable as a DNS query
// name: at most 253 octets without the trailing dot, labels of 1 to 63
// octets, no whitespace or control characters. It deliberately does not
// enforce LDH syntax because TXT owners such as "_dmarc" or "_domainkey" use
// underscores.
func ValidDomain(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c <= ' ' || c >= 0x7f {
				return false
			}
		}
	}
	return true
}

// ReverseName returns the in-addr.arpa or ip6.arpa name for addr.
func ReverseName(addr netip.Addr) string {
	addr = addr.Unmap()
	var b strings.Builder
	if addr.Is4() {
		a := addr.As4()
		for i := 3; i >= 0; i-- {
			b.WriteString(itoa(int(a[i])))
			b.WriteByte('.')
		}
		b.WriteString("in-addr.arpa.")
		return b.String()
	}
	const hexDigits = "0123456789abcdef"
	a := addr.As16()
	for i := 15; i >= 0; i-- {
		b.WriteByte(hexDigits[a[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(hexDigits[a[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa.")
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
