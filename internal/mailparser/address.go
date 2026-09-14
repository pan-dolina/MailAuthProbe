package mailparser

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// Address is a parsed mailbox.
type Address struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
	Domain  string `json:"domain"`
}

// ParseAddressList parses a header value holding a list of mailboxes.
func ParseAddressList(value string) ([]Address, error) {
	list, err := (&mail.AddressParser{}).ParseList(value)
	if err != nil {
		return nil, err
	}
	out := make([]Address, 0, len(list))
	for _, a := range list {
		out = append(out, Address{Name: a.Name, Address: a.Address, Domain: DomainOf(a.Address)})
	}
	return out, nil
}

// DomainOf returns the lower-cased domain part of an address.
func DomainOf(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(addr[i+1:], "<> \t[]"), "."))
}

// ErrNullReversePath is returned for "Return-Path: <>".
var ErrNullReversePath = errors.New("null reverse-path")

// ParseReturnPath parses a Return-Path value, which carries the envelope
// MAIL FROM recorded at final delivery.
func ParseReturnPath(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "<>" {
		return "", ErrNullReversePath
	}
	v = strings.TrimSuffix(strings.TrimPrefix(v, "<"), ">")
	if !strings.Contains(v, "@") {
		return "", fmt.Errorf("invalid Return-Path %q", value)
	}
	a, err := mail.ParseAddress("<" + v + ">")
	if err != nil {
		return "", fmt.Errorf("invalid Return-Path %q: %w", value, err)
	}
	return a.Address, nil
}

// ParseDate parses an RFC 5322 date.
func ParseDate(value string) (time.Time, error) {
	return mail.ParseDate(strings.TrimSpace(value))
}
