package dnsresolver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestValidDomain(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"example.com.", true},
		{"_dmarc.example.com", true},
		{"s1._domainkey.example.com", true},
		{"localhost", true},
		{"", false},
		{".", false},
		{"a..b", false},
		{"exa mple.com", false},
		{strings.Repeat("a", 64) + ".com", false},
		{strings.Repeat("a", 63) + ".com", true},
		{strings.Repeat("abcdefghi.", 26), false},
		{"tab\t.com", false},
		{"ünï.com", false},
	}
	for _, tt := range tests {
		if got := ValidDomain(tt.name); got != tt.want {
			t.Errorf("ValidDomain(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestReverseName(t *testing.T) {
	tests := []struct{ addr, want string }{
		{"192.0.2.1", "1.2.0.192.in-addr.arpa."},
		{"::ffff:198.51.100.10", "10.100.51.198.in-addr.arpa."},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"0.0.0.0", "0.0.0.0.in-addr.arpa."},
	}
	for _, tt := range tests {
		if got := ReverseName(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("ReverseName(%s) = %s, want %s", tt.addr, got, tt.want)
		}
	}
}

func TestParseServerAddress(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"127.0.0.1", "127.0.0.1:53", false},
		{"127.0.0.1:5353", "127.0.0.1:5353", false},
		{"::1", "[::1]:53", false},
		{"[::1]", "[::1]:53", false},
		{"[2001:db8::53]:853", "[2001:db8::53]:853", false},
		{" 192.0.2.53 ", "192.0.2.53:53", false},
		{"dns.example", "", true},
		{"127.0.0.1:0", "", true},
		{"127.0.0.1:99999", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := ParseServerAddress(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseServerAddress(%q) = %q, %v; want %q, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestParseResolvConf(t *testing.T) {
	conf := `# generated
domain example.com
nameserver 192.0.2.53
nameserver   2001:db8::53
nameserver bogus
options ndots:2
`
	got, err := parseResolvConf(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.53:53", "[2001:db8::53]:53"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestErrorClassification(t *testing.T) {
	tests := []struct {
		err            error
		nx, temp, infr bool
	}{
		{&Error{Kind: KindNXDomain}, true, false, false},
		{&Error{Kind: KindTemporary}, false, true, true},
		{&Error{Kind: KindRefused}, false, true, true},
		{&Error{Kind: KindMalformed}, false, true, true},
		{&Error{Kind: KindBudget}, false, true, false},
		{&Error{Kind: KindInvalidName}, false, false, false},
		{context.DeadlineExceeded, false, true, true},
		{nil, false, false, false},
	}
	for _, tt := range tests {
		if IsNXDomain(tt.err) != tt.nx || IsTemporary(tt.err) != tt.temp || IsInfrastructure(tt.err) != tt.infr {
			t.Errorf("%v: nx=%v temp=%v infra=%v", tt.err, IsNXDomain(tt.err), IsTemporary(tt.err), IsInfrastructure(tt.err))
		}
	}
}

// countingResolver records calls and answers every TXT query with the name.
type countingResolver struct {
	calls int
	err   error
}

func (c *countingResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	return []string{name}, nil
}
func (c *countingResolver) LookupMX(context.Context, string) ([]MX, error) {
	c.calls++
	return nil, c.err
}
func (c *countingResolver) LookupA(context.Context, string) ([]netip.Addr, error) {
	c.calls++
	return nil, c.err
}
func (c *countingResolver) LookupAAAA(context.Context, string) ([]netip.Addr, error) {
	c.calls++
	return nil, c.err
}
func (c *countingResolver) LookupCNAME(context.Context, string) (string, error) {
	c.calls++
	return "", c.err
}
func (c *countingResolver) LookupPTR(context.Context, netip.Addr) ([]string, error) {
	c.calls++
	return nil, c.err
}

func TestBudget(t *testing.T) {
	ctx := context.Background()
	next := &countingResolver{}
	b := WithBudget(next, 3)
	for range 3 {
		if _, err := b.LookupTXT(ctx, "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	_, err := b.LookupMX(ctx, "example.com")
	if KindOf(err) != KindBudget {
		t.Fatalf("err = %v, want budget error", err)
	}
	if next.calls != 3 || !b.Exhausted() || b.Used() != 4 {
		t.Errorf("calls=%d exhausted=%v used=%d", next.calls, b.Exhausted(), b.Used())
	}
}

func TestCache(t *testing.T) {
	ctx := context.Background()
	next := &countingResolver{}
	c := NewCache(next)
	for range 3 {
		got, err := c.LookupTXT(ctx, "Example.COM.")
		if err != nil || len(got) != 1 {
			t.Fatal(got, err)
		}
		_, _ = c.LookupTXT(ctx, "example.com")
	}
	if next.calls != 1 {
		t.Errorf("calls = %d, want 1", next.calls)
	}

	next = &countingResolver{err: &Error{Kind: KindTemporary}}
	c = NewCache(next)
	_, _ = c.LookupA(ctx, "example.com")
	_, _ = c.LookupA(ctx, "example.com")
	if next.calls != 2 {
		t.Errorf("temporary errors must not be cached; calls = %d", next.calls)
	}

	next = &countingResolver{err: &Error{Kind: KindNXDomain}}
	c = NewCache(next)
	_, _ = c.LookupA(ctx, "example.com")
	_, err := c.LookupA(ctx, "example.com")
	if next.calls != 1 || !IsNXDomain(err) {
		t.Errorf("NXDOMAIN should be cached; calls = %d, err = %v", next.calls, err)
	}
}

func mustName(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func TestAnswersForFollowsCNAMEChain(t *testing.T) {
	hdr := func(name string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: mustName(name), Type: typ, Class: dnsmessage.ClassINET}
	}
	msg := &dnsmessage.Message{Answers: []dnsmessage.Resource{
		{Header: hdr("www.example.com.", dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: mustName("edge.example.net.")}},
		{Header: hdr("EDGE.example.net.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}},
		{Header: hdr("unrelated.example.org.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}}},
	}}
	got := answersFor(msg, "www.example.com.", dnsmessage.TypeA)
	if len(got) != 1 || got[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 1} {
		t.Errorf("got %v", got)
	}
}

func TestClientTimeout(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on UDP:", err)
	}
	defer pc.Close()
	c := &Client{Servers: []string{pc.LocalAddr().String()}, Timeout: 50 * time.Millisecond, Attempts: 2}
	start := time.Now()
	_, err = c.LookupTXT(context.Background(), "example.com")
	if KindOf(err) != KindTemporary {
		t.Fatalf("err = %v, want temporary", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %v", elapsed)
	}
}

func TestClientTCPResponseTooLarge(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Skip("cannot bind TCP on the UDP port:", err)
	}
	defer ln.Close()

	// UDP: answer every query with a truncated response.
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Truncated: true}, Questions: q.Questions}
			b, _ := resp.Pack()
			_, _ = pc.WriteTo(b, addr)
		}
	}()
	// TCP: announce a response larger than the client accepts.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var l [2]byte
		_, _ = conn.Read(l[:])
		binary.BigEndian.PutUint16(l[:], 60000)
		_, _ = conn.Write(l[:])
	}()

	c := &Client{Servers: []string{pc.LocalAddr().String()}, Timeout: time.Second, Attempts: 1, MaxResponseSize: 4096}
	_, err = c.LookupTXT(context.Background(), "example.com")
	if KindOf(err) != KindTooLarge {
		t.Fatalf("err = %v, want too large", err)
	}
	var de *Error
	if !errors.As(err, &de) || de.Server == "" || de.Type != "TXT" {
		t.Errorf("error lacks context: %#v", de)
	}
}

func TestClientRejectsInvalidName(t *testing.T) {
	c := &Client{Servers: []string{"127.0.0.1:1"}}
	_, err := c.LookupTXT(context.Background(), "bad name.example")
	if KindOf(err) != KindInvalidName {
		t.Fatalf("err = %v", err)
	}
}

// slowResolver blocks TXT lookups until released and counts them.
type slowResolver struct {
	countingResolver
	release chan struct{}
	mu      sync.Mutex
}

func (s *slowResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	<-s.release
	return []string{name}, nil
}

func TestCacheDeduplicatesConcurrentLookups(t *testing.T) {
	next := &slowResolver{release: make(chan struct{})}
	c := NewCache(next)
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := c.LookupTXT(context.Background(), "example.com"); err != nil || len(got) != 1 {
				t.Errorf("got %v, %v", got, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(next.release)
	wg.Wait()
	if next.calls != 1 {
		t.Errorf("calls = %d, want 1", next.calls)
	}
}
