// Package netutil contains small address and host name helpers shared by
// protocol packages.
package netutil

import (
	"net/netip"
	"strings"
)

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001:2::/48"),    // benchmarking
	netip.MustParsePrefix("fc00::/7"),       // unique local
	netip.MustParsePrefix("255.255.255.255/32"),
}

// IsNonPublic reports whether addr can never be reached over the public
// Internet: private, loopback, link-local, unspecified, multicast, CGNAT and
// reserved ranges.
//
// Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
// 2001:db8::/32) are deliberately treated as public so that examples and test
// fixtures based on them behave like real deployments.
func IsNonPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() ||
		addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsHostname reports whether name is a syntactically valid host name
// (RFC 1123 LDH labels), with or without a trailing dot.
func IsHostname(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
