package dnsresolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Defaults for Client.
const (
	DefaultQueryTimeout    = 5 * time.Second
	DefaultAttempts        = 2
	DefaultMaxResponseSize = 32 * 1024
	// DefaultUDPSize is the EDNS(0) payload size advertised to servers. 1232
	// avoids IP fragmentation on virtually all paths (DNS Flag Day 2020).
	DefaultUDPSize = 1232
	maxCNAMEChain  = 8
)

// Client is a stub resolver that sends recursive queries to configured
// servers over UDP, retrying over TCP when a response is truncated.
type Client struct {
	// Servers are host:port addresses tried in order.
	Servers []string
	// Timeout bounds each attempt. Zero means DefaultQueryTimeout.
	Timeout time.Duration
	// Attempts per server for UDP. Zero means DefaultAttempts.
	Attempts int
	// MaxResponseSize caps accepted responses. Zero means
	// DefaultMaxResponseSize.
	MaxResponseSize int
	// Dialer is used to open connections; nil means a zero net.Dialer.
	Dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
}

var _ Resolver = (*Client)(nil)

// LookupTXT implements Resolver.
func (c *Client) LookupTXT(ctx context.Context, name string) ([]string, error) {
	rrs, err := c.lookup(ctx, name, dnsmessage.TypeTXT)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, rr := range rrs {
		if txt, ok := rr.Body.(*dnsmessage.TXTResource); ok {
			out = append(out, strings.Join(txt.TXT, ""))
		}
	}
	return out, nil
}

// LookupMX implements Resolver.
func (c *Client) LookupMX(ctx context.Context, name string) ([]MX, error) {
	rrs, err := c.lookup(ctx, name, dnsmessage.TypeMX)
	if err != nil {
		return nil, err
	}
	out := []MX{}
	for _, rr := range rrs {
		if mx, ok := rr.Body.(*dnsmessage.MXResource); ok {
			out = append(out, MX{Host: Trim(mx.MX.String()), Preference: mx.Pref})
		}
	}
	return out, nil
}

// LookupA implements Resolver.
func (c *Client) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	rrs, err := c.lookup(ctx, name, dnsmessage.TypeA)
	if err != nil {
		return nil, err
	}
	out := []netip.Addr{}
	for _, rr := range rrs {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(a.A))
		}
	}
	return out, nil
}

// LookupAAAA implements Resolver.
func (c *Client) LookupAAAA(ctx context.Context, name string) ([]netip.Addr, error) {
	rrs, err := c.lookup(ctx, name, dnsmessage.TypeAAAA)
	if err != nil {
		return nil, err
	}
	out := []netip.Addr{}
	for _, rr := range rrs {
		if a, ok := rr.Body.(*dnsmessage.AAAAResource); ok {
			out = append(out, netip.AddrFrom16(a.AAAA))
		}
	}
	return out, nil
}

// LookupCNAME implements Resolver.
func (c *Client) LookupCNAME(ctx context.Context, name string) (string, error) {
	msg, err := c.exchange(ctx, name, dnsmessage.TypeCNAME)
	if err != nil {
		return "", err
	}
	owner := Fqdn(name)
	for _, rr := range msg.Answers {
		if cn, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && strings.EqualFold(rr.Header.Name.String(), owner) {
			return Trim(cn.CNAME.String()), nil
		}
	}
	return "", nil
}

// LookupPTR implements Resolver.
func (c *Client) LookupPTR(ctx context.Context, addr netip.Addr) ([]string, error) {
	rrs, err := c.lookup(ctx, ReverseName(addr), dnsmessage.TypePTR)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, rr := range rrs {
		if p, ok := rr.Body.(*dnsmessage.PTRResource); ok {
			out = append(out, Trim(p.PTR.String()))
		}
	}
	return out, nil
}

// lookup returns the answer records of qtype owned by name or by any name in
// its CNAME chain.
func (c *Client) lookup(ctx context.Context, name string, qtype dnsmessage.Type) ([]dnsmessage.Resource, error) {
	msg, err := c.exchange(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	return answersFor(msg, Fqdn(name), qtype), nil
}

func answersFor(msg *dnsmessage.Message, owner string, qtype dnsmessage.Type) []dnsmessage.Resource {
	chain := map[string]bool{owner: true}
	target := owner
	for range maxCNAMEChain {
		next := ""
		for _, rr := range msg.Answers {
			if cn, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && strings.EqualFold(rr.Header.Name.String(), target) {
				next = strings.ToLower(cn.CNAME.String())
				break
			}
		}
		if next == "" || chain[next] {
			break
		}
		chain[next] = true
		target = next
	}
	var out []dnsmessage.Resource
	for _, rr := range msg.Answers {
		if rr.Header.Type == qtype && chain[strings.ToLower(rr.Header.Name.String())] {
			out = append(out, rr)
		}
	}
	return out
}

func typeName(t dnsmessage.Type) string {
	return strings.TrimPrefix(t.String(), "Type")
}

func (c *Client) exchange(ctx context.Context, name string, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	derr := func(kind Kind, server string, err error) *Error {
		return &Error{Kind: kind, Name: Trim(name), Type: typeName(qtype), Server: server, Err: err}
	}
	if !ValidDomain(name) {
		return nil, derr(KindInvalidName, "", nil)
	}
	qname, err := dnsmessage.NewName(Fqdn(name))
	if err != nil {
		return nil, derr(KindInvalidName, "", err)
	}
	if len(c.Servers) == 0 {
		return nil, derr(KindTemporary, "", errors.New("no DNS servers configured"))
	}
	q := dnsmessage.Question{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}

	attempts := c.Attempts
	if attempts <= 0 {
		attempts = DefaultAttempts
	}
	var lastErr *Error
	for _, server := range c.Servers {
		for range attempts {
			if err := ctx.Err(); err != nil {
				return nil, derr(KindTemporary, server, err)
			}
			msg, err := c.exchangeOnce(ctx, server, q)
			if err == nil {
				switch msg.RCode {
				case dnsmessage.RCodeSuccess:
					return msg, nil
				case dnsmessage.RCodeNameError:
					return nil, derr(KindNXDomain, "", nil)
				case dnsmessage.RCodeRefused:
					lastErr = derr(KindRefused, server, nil)
				default:
					lastErr = derr(KindTemporary, server, fmt.Errorf("rcode %s", strings.TrimPrefix(msg.RCode.String(), "RCode")))
				}
				break // a definite answer from this server; try the next server
			}
			var de *Error
			if errors.As(err, &de) {
				de.Name, de.Type, de.Server = Trim(name), typeName(qtype), server
				lastErr = de
			} else {
				lastErr = derr(KindTemporary, server, err)
			}
			if lastErr.Kind != KindTemporary {
				break
			}
		}
	}
	return nil, lastErr
}

func (c *Client) exchangeOnce(ctx context.Context, server string, q dnsmessage.Question) (*dnsmessage.Message, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	msg, err := c.roundTrip(ctx, "udp", server, id, q)
	if err != nil {
		return nil, err
	}
	if msg.Truncated {
		return c.roundTrip(ctx, "tcp", server, id, q)
	}
	return msg, nil
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func (c *Client) roundTrip(ctx context.Context, network, server string, id uint16, q dnsmessage.Question) (*dnsmessage.Message, error) {
	query, err := buildQuery(id, q)
	if err != nil {
		return nil, &Error{Kind: KindInvalidName, Err: err}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultQueryTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	} = &net.Dialer{}
	if c.Dialer != nil {
		dialer = c.Dialer
	}
	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, &Error{Kind: KindTemporary, Err: err}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// Unblock reads when the parent context is cancelled.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	maxSize := c.MaxResponseSize
	if maxSize <= 0 {
		maxSize = DefaultMaxResponseSize
	}
	if network == "udp" {
		return exchangeUDP(conn, query, id, q, maxSize)
	}
	return exchangeTCP(conn, query, id, q, maxSize)
}

func buildQuery(id uint16, q dnsmessage.Question) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(DefaultUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func exchangeUDP(conn net.Conn, query []byte, id uint16, q dnsmessage.Question, maxSize int) (*dnsmessage.Message, error) {
	if _, err := conn.Write(query); err != nil {
		return nil, classifyNetErr(err)
	}
	buf := make([]byte, min(maxSize, 65535)+1)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, classifyNetErr(err)
		}
		if n > maxSize {
			return nil, &Error{Kind: KindTooLarge, Err: fmt.Errorf("UDP response exceeds %d bytes", maxSize)}
		}
		msg, err := parseResponse(buf[:n], id, q)
		if errors.Is(err, errMismatch) {
			// Possibly a late or spoofed datagram; keep waiting for ours.
			continue
		}
		return msg, err
	}
}

func exchangeTCP(conn net.Conn, query []byte, id uint16, q dnsmessage.Question, maxSize int) (*dnsmessage.Message, error) {
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query))) // #nosec G115 -- queries are far below 64 KiB
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, classifyNetErr(err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, classifyNetErr(err)
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size > maxSize {
		return nil, &Error{Kind: KindTooLarge, Err: fmt.Errorf("TCP response of %d bytes exceeds %d", size, maxSize)}
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, classifyNetErr(err)
	}
	msg, err := parseResponse(buf, id, q)
	if errors.Is(err, errMismatch) {
		return nil, &Error{Kind: KindMalformed, Err: err}
	}
	if err == nil && msg.Truncated {
		return nil, &Error{Kind: KindMalformed, Err: errors.New("truncated response over TCP")}
	}
	return msg, err
}

var errMismatch = errors.New("response does not match query")

func parseResponse(b []byte, id uint16, q dnsmessage.Question) (*dnsmessage.Message, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(b); err != nil {
		// A datagram that does not even carry our ID is treated as noise.
		if len(b) < 2 || binary.BigEndian.Uint16(b) != id {
			return nil, errMismatch
		}
		return nil, &Error{Kind: KindMalformed, Err: err}
	}
	if msg.ID != id || !msg.Response {
		return nil, errMismatch
	}
	// Some servers omit the question in truncated or error responses;
	// when a question is present it must be ours.
	questionOK := len(msg.Questions) == 1 && msg.Questions[0].Type == q.Type &&
		msg.Questions[0].Class == q.Class && strings.EqualFold(msg.Questions[0].Name.String(), q.Name.String())
	switch {
	case len(msg.Questions) > 0 && !questionOK:
		return nil, &Error{Kind: KindMalformed, Err: errMismatch}
	case msg.Truncated:
		return &msg, nil
	case !questionOK && (msg.RCode == dnsmessage.RCodeSuccess || msg.RCode == dnsmessage.RCodeNameError):
		return nil, &Error{Kind: KindMalformed, Err: errMismatch}
	}
	return &msg, nil
}

func classifyNetErr(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: KindTemporary, Err: errors.New("timeout")}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &Error{Kind: KindMalformed, Err: errors.New("connection closed before full response")}
	}
	return &Error{Kind: KindTemporary, Err: err}
}
