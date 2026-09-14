package dnsresolver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Options configure New.
type Options struct {
	// Server is an explicit resolver address ("host", "host:port",
	// "[v6]:port"). Empty means the system configuration.
	Server string
	// Timeout per query attempt.
	Timeout time.Duration
	// MaxResponseSize caps accepted responses.
	MaxResponseSize int
}

// New returns a resolver for the given options. With no explicit server it
// uses the name servers from /etc/resolv.conf, and falls back to the
// operating system resolver where that file does not exist (Windows).
func New(opts Options) (Resolver, error) {
	var servers []string
	if opts.Server != "" {
		addr, err := ParseServerAddress(opts.Server)
		if err != nil {
			return nil, err
		}
		servers = []string{addr}
	} else {
		s, err := systemServers("/etc/resolv.conf")
		if err != nil || len(s) == 0 {
			return &StdResolver{Resolver: net.DefaultResolver}, nil
		}
		servers = s
	}
	return &Client{Servers: servers, Timeout: opts.Timeout, MaxResponseSize: opts.MaxResponseSize}, nil
}

// ParseServerAddress normalises a resolver address to host:port, defaulting
// to port 53. Only IP addresses are accepted so that resolving the resolver
// never depends on DNS itself.
func ParseServerAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty resolver address")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return "", fmt.Errorf("invalid resolver port in %q", s)
		}
		return ap.String(), nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	return "", fmt.Errorf("invalid resolver address %q: want an IP address with optional port", s)
}

func systemServers(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- fixed system path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseResolvConf(f)
}

func parseResolvConf(r io.Reader) ([]string, error) {
	var servers []string
	sc := bufio.NewScanner(io.LimitReader(r, 64*1024))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr, err := ParseServerAddress(fields[1]); err == nil {
			servers = append(servers, addr)
		}
	}
	return servers, sc.Err()
}
