package dnstest

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// Server serves a Zone over UDP and TCP on the same localhost port.
type Server struct {
	zone *Zone
	pc   net.PacketConn
	ln   net.Listener
	wg   sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// NewServer starts a server for zone on 127.0.0.1 with an ephemeral port.
func NewServer(zone *Zone) (*Server, error) {
	return Listen(zone, "127.0.0.1:0")
}

// Listen starts a server for zone on addr. When the port is 0 an ephemeral
// port that is free for both UDP and TCP is chosen.
func Listen(zone *Zone, addr string) (*Server, error) {
	var lastErr error
	for range 20 {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, err
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			lastErr = err
			if strings.HasSuffix(addr, ":0") {
				continue
			}
			return nil, err
		}
		s := &Server{zone: zone, pc: pc, ln: ln, conns: map[net.Conn]struct{}{}}
		s.wg.Add(2)
		go s.serveUDP()
		go s.serveTCP()
		return s, nil
	}
	return nil, lastErr
}

// Addr returns the host:port the server listens on.
func (s *Server) Addr() string { return s.pc.LocalAddr().String() }

// Close stops the server and waits for its goroutines.
func (s *Server) Close() error {
	err := errors.Join(s.pc.Close(), s.ln.Close())
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := s.handle(buf[:n], true); resp != nil {
			_, _ = s.pc.WriteTo(resp, addr)
		}
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				conn.Close()
			}()
			for {
				var l [2]byte
				if _, err := io.ReadFull(conn, l[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				resp := s.handle(req, false)
				if resp == nil {
					continue
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp))) // #nosec G115 -- bounded by dnsmessage
				copy(out[2:], resp)
				if _, err := conn.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

var typeNames = map[dnsmessage.Type]string{
	dnsmessage.TypeA:     "A",
	dnsmessage.TypeAAAA:  "AAAA",
	dnsmessage.TypeMX:    "MX",
	dnsmessage.TypeTXT:   "TXT",
	dnsmessage.TypeCNAME: "CNAME",
	dnsmessage.TypePTR:   "PTR",
}

// handle builds the wire response for a query, or nil to stay silent.
func (s *Server) handle(req []byte, udp bool) []byte {
	var q dnsmessage.Message
	if err := q.Unpack(req); err != nil || len(q.Questions) != 1 {
		return nil
	}
	question := q.Questions[0]
	hdr := dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}

	qtype, known := typeNames[question.Type]
	if !known {
		qtype = question.Type.String()
	}
	res := s.zone.resolve(question.Name.String(), qtype)
	switch res.behavior {
	case Timeout:
		return nil
	case Malformed:
		// Our ID followed by bytes that do not form a valid message.
		return []byte{byte(q.ID >> 8), byte(q.ID), 0x81, 0x80, 0x00, 0x01, 0xff, 0xff, 0xde, 0xad}
	case ServFail:
		hdr.RCode = dnsmessage.RCodeServerFailure
	case Refused:
		hdr.RCode = dnsmessage.RCodeRefused
	case Truncate:
		if udp {
			hdr.Truncated = true
			return pack(dnsmessage.Message{Header: hdr, Questions: q.Questions})
		}
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return pack(dnsmessage.Message{Header: hdr, Questions: q.Questions})
	}
	if res.nxdomain {
		hdr.RCode = dnsmessage.RCodeNameError
	}

	msg := dnsmessage.Message{Header: hdr, Questions: q.Questions}
	for _, r := range append(res.chain, res.answers...) {
		if rr, ok := toResource(r); ok {
			msg.Answers = append(msg.Answers, rr)
		}
	}
	b := pack(msg)
	if udp && len(b) > udpLimit(&q) {
		hdr.Truncated = true
		return pack(dnsmessage.Message{Header: hdr, Questions: q.Questions})
	}
	return b
}

func udpLimit(q *dnsmessage.Message) int {
	for _, rr := range q.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			return max(512, int(rr.Header.Class))
		}
	}
	return 512
}

func pack(m dnsmessage.Message) []byte {
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

func toResource(r Record) (dnsmessage.Resource, bool) {
	name, err := dnsmessage.NewName(r.Name)
	if err != nil {
		return dnsmessage.Resource{}, false
	}
	h := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 300}
	target := func() (dnsmessage.Name, bool) {
		n, err := dnsmessage.NewName(r.Target)
		return n, err == nil
	}
	switch r.Type {
	case "A":
		h.Type = dnsmessage.TypeA
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: r.Addr.As4()}}, true
	case "AAAA":
		h.Type = dnsmessage.TypeAAAA
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: r.Addr.As16()}}, true
	case "MX":
		n, ok := target()
		h.Type = dnsmessage.TypeMX
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.MXResource{Pref: r.Pref, MX: n}}, ok
	case "CNAME":
		n, ok := target()
		h.Type = dnsmessage.TypeCNAME
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.CNAMEResource{CNAME: n}}, ok
	case "PTR":
		n, ok := target()
		h.Type = dnsmessage.TypePTR
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.PTRResource{PTR: n}}, ok
	case "TXT":
		h.Type = dnsmessage.TypeTXT
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.TXTResource{TXT: splitTXT(r.Text)}}, true
	}
	return dnsmessage.Resource{}, false
}

// splitTXT splits text into character-strings of at most 255 octets.
func splitTXT(s string) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	for len(s) > 255 {
		out = append(out, s[:255])
		s = s[255:]
	}
	return append(out, s)
}
