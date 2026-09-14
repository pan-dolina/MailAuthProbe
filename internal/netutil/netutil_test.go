package netutil

import (
	"net/netip"
	"testing"
)

func TestIsNonPublic(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.10.10", true},
		{"0.0.0.0", true},
		{"100.64.0.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"::1", true},
		{"fe80::1", true},
		{"fd00::1", true},
		{"::ffff:10.0.0.1", true},
		{"64:ff9b::a9fe:a9fe", true},
		{"64:ff9b::808:808", false},
		{"2002:c0a8:0101::1", true},
		{"2002:0808:0808::1", false},
		{"::10.0.0.1", true},
		{"2001:0:4136:e378:8000:63bf:f5ff:fffe", true},
		{"fec0::1", true},
		{"192.88.99.1", true},
		{"8.8.8.8", false},
		{"192.0.2.10", false},
		{"2001:db8::1", false},
		{"2a00:1450:4001::1", false},
	}
	for _, tt := range tests {
		if got := IsNonPublic(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("IsNonPublic(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestIsHostname(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"mx1.example.com", true},
		{"mx1.example.com.", true},
		{"a-b.example", true},
		{"123.example", true},
		{"_spf.example.com", false},
		{"-mx.example.com", false},
		{"mx-.example.com", false},
		{"mx..example.com", false},
		{"", false},
		{"mx example.com", false},
	}
	for _, tt := range tests {
		if got := IsHostname(tt.name); got != tt.want {
			t.Errorf("IsHostname(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
