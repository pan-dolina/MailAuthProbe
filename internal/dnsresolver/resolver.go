// Package dnsresolver provides the DNS access layer used by all protocol
// checks.
//
// The Resolver interface distinguishes the outcomes that mail authentication
// standards care about: a name that does not exist (NXDOMAIN), a name that
// exists without records of the requested type (empty result, nil error),
// temporary failures and malformed responses. Implementations must be safe for
// concurrent use.
package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// Resolver performs the DNS lookups needed by MailAuthProbe.
//
// A lookup that succeeds but returns no records of the requested type
// ("NODATA") yields an empty slice and a nil error. A name that does not exist
// yields an *Error with Kind KindNXDomain.
type Resolver interface {
	// LookupTXT returns TXT records. Character-strings within one record are
	// concatenated without separators, as required by SPF, DKIM and DMARC.
	LookupTXT(ctx context.Context, name string) ([]string, error)
	// LookupMX returns MX records in the order received.
	LookupMX(ctx context.Context, name string) ([]MX, error)
	// LookupA returns IPv4 addresses, following CNAMEs.
	LookupA(ctx context.Context, name string) ([]netip.Addr, error)
	// LookupAAAA returns IPv6 addresses, following CNAMEs.
	LookupAAAA(ctx context.Context, name string) ([]netip.Addr, error)
	// LookupCNAME returns the CNAME target owned by name, or "" if name
	// has no CNAME record.
	LookupCNAME(ctx context.Context, name string) (string, error)
	// LookupPTR returns the PTR names for addr.
	LookupPTR(ctx context.Context, addr netip.Addr) ([]string, error)
}

// MX is a mail exchanger record. Host is a fully qualified name without the
// trailing dot; the null MX target "." is represented as ".".
type MX struct {
	Host       string `json:"host"`
	Preference uint16 `json:"preference"`
}

// Kind classifies DNS errors.
type Kind int

// Error kinds.
const (
	// KindNXDomain: the name does not exist (RCODE 3).
	KindNXDomain Kind = iota + 1
	// KindTemporary: SERVFAIL, timeout or network failure. Retrying may help.
	KindTemporary
	// KindRefused: the server refused the query (RCODE 5).
	KindRefused
	// KindMalformed: the response could not be parsed or did not match the
	// query.
	KindMalformed
	// KindTooLarge: the response exceeded the configured size limit.
	KindTooLarge
	// KindBudget: the per-scan query budget is exhausted.
	KindBudget
	// KindInvalidName: the query name is not a valid DNS name.
	KindInvalidName
)

func (k Kind) String() string {
	switch k {
	case KindNXDomain:
		return "nxdomain"
	case KindTemporary:
		return "temporary failure"
	case KindRefused:
		return "refused"
	case KindMalformed:
		return "malformed response"
	case KindTooLarge:
		return "response too large"
	case KindBudget:
		return "query budget exhausted"
	case KindInvalidName:
		return "invalid name"
	default:
		return fmt.Sprintf("Kind(%d)", int(k))
	}
}

// Error describes a failed lookup.
type Error struct {
	Kind   Kind
	Name   string
	Type   string
	Server string
	Err    error
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("dns %s %s: %s", e.Type, e.Name, e.Kind)
	if e.Server != "" {
		msg += " (server " + e.Server + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf returns the Kind of err, or 0 if err is not a DNS error.
func KindOf(err error) Kind {
	var de *Error
	if errors.As(err, &de) {
		return de.Kind
	}
	return 0
}

// IsNXDomain reports whether err means the queried name does not exist.
func IsNXDomain(err error) bool { return KindOf(err) == KindNXDomain }

// IsTemporary reports whether err is a failure that may succeed on retry.
// This corresponds to SPF "temperror" and DKIM/DMARC "temperror" semantics.
func IsTemporary(err error) bool {
	if err == nil {
		return false
	}
	switch KindOf(err) {
	case KindNXDomain, KindInvalidName:
		return false
	case KindTemporary, KindRefused, KindMalformed, KindTooLarge, KindBudget:
		return true
	}
	// Context cancellation and unknown errors are treated as temporary: the
	// answer is unknown, not negative.
	return true
}

// IsInfrastructure reports whether err indicates that the resolver itself
// could not be used (network failure, timeout, refusal), as opposed to a
// property of the queried data.
func IsInfrastructure(err error) bool {
	switch KindOf(err) {
	case KindTemporary, KindRefused:
		return true
	case 0:
		return err != nil
	}
	return false
}
