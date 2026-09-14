package received

import (
	"fmt"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/findings"
	"github.com/marcindolinski/mailauthprobe/internal/netutil"
)

// MaxHops bounds the number of Received headers analysed.
const MaxHops = 100

// clockSkew is the tolerance before timestamps going backwards are reported.
const clockSkew = 5 * time.Minute

// Chain is the transport path, origin first.
type Chain struct {
	Hops []Hop `json:"hops"`
	// Truncated is set when more than MaxHops headers were present.
	Truncated bool               `json:"truncated,omitempty"`
	Findings  []findings.Finding `json:"-"`
}

// Build parses Received header values given in header order (most recent
// first) and returns the chain in transport order.
func Build(values []string) *Chain {
	c := &Chain{Hops: []Hop{}}
	add := func(f findings.Finding) { c.Findings = append(c.Findings, f) }
	if len(values) == 0 {
		add(findings.RcvdNone.New("", "The message has no Received headers. It was either never transported over SMTP or its trace headers were removed."))
		return c
	}
	if len(values) > MaxHops {
		c.Truncated = true
		add(findings.RcvdTooMany.New("", fmt.Sprintf("The message has %d Received headers; only the %d most recent were analysed. Very long chains indicate a mail loop or padding.", len(values), MaxHops)))
		values = values[:MaxHops]
	}
	for i := len(values) - 1; i >= 0; i-- {
		h := Parse(values[i])
		h.Index = len(c.Hops) + 1
		c.Hops = append(c.Hops, h)
	}

	var prev *Hop
	for i := range c.Hops {
		h := &c.Hops[i]
		for _, p := range h.Problems {
			switch p {
			case "missing date":
				add(findings.RcvdNoDate.New(hopSubject(h), fmt.Sprintf("Received header #%d has no date.", h.Index), h.Raw))
			default:
				add(findings.RcvdUnparseable.New(hopSubject(h), fmt.Sprintf("Received header #%d could not be fully parsed: %s.", h.Index, p), h.Raw))
			}
		}
		if prev != nil && prev.Timestamp != nil && h.Timestamp != nil {
			d := h.Timestamp.Sub(*prev.Timestamp)
			h.Delay = &d
			switch {
			case d < -clockSkew:
				add(findings.RcvdTimeTravel.New(hopSubject(h),
					fmt.Sprintf("Hop #%d is timestamped %s before hop #%d. Clocks may be wrong, or earlier headers may have been forged by the sender.", h.Index, (-d).Round(time.Second), prev.Index),
					prev.Raw, h.Raw))
			case d > time.Hour:
				add(findings.RcvdDelay.New(hopSubject(h), fmt.Sprintf("The message spent %s between hop #%d and hop #%d.", d.Round(time.Second), prev.Index, h.Index)))
			}
		}
		if h.TLS != nil && !h.TLS.Used {
			if ip, ok := h.Addr(); !ok || !ip.IsLoopback() {
				add(findings.RcvdNoTLS.New(hopSubject(h), fmt.Sprintf("Hop #%d used %s without TLS.", h.Index, h.Protocol), h.Raw))
			}
		}
		prev = h
	}
	return c
}

func hopSubject(h *Hop) string {
	if h.By != nil {
		return h.By.Value
	}
	return fmt.Sprintf("hop #%d", h.Index)
}

// Source describes the SMTP client inferred from the chain.
type Source struct {
	IP       string `json:"ip"`
	HELO     string `json:"helo,omitempty"`
	HopIndex int    `json:"hop_index"`
	Reason   string `json:"reason"`
}

// InferSource guesses the client that handed the message to the receiving
// organization: the most recent hop whose client address is publicly
// routable. The result is always an inference; the receiving MTA's
// boundary is not known.
func (c *Chain) InferSource() (*Source, bool) {
	for i := len(c.Hops) - 1; i >= 0; i-- {
		h := &c.Hops[i]
		ip, ok := h.Addr()
		if !ok || netutil.IsNonPublic(ip) {
			continue
		}
		s := &Source{IP: ip.String(), HopIndex: h.Index,
			Reason: fmt.Sprintf("client address of the most recent Received header with a public IP (hop #%d)", h.Index)}
		if h.HELO != nil {
			s.HELO = h.HELO.Value
		}
		return s, true
	}
	return nil, false
}
