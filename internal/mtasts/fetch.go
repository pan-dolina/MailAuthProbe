package mtasts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver"
	"github.com/pan-dolina/mailauthprobe/internal/netutil"
)

// MaxPolicySize caps the policy body. RFC 8461 policies are a few hundred
// bytes.
const MaxPolicySize = 64 << 10

// Response is the result of fetching a policy.
type Response struct {
	URL         string       `json:"url"`
	StatusCode  int          `json:"status_code,omitempty"`
	ContentType string       `json:"content_type,omitempty"`
	Body        string       `json:"-"`
	Certificate *Certificate `json:"certificate,omitempty"`
}

// Certificate summarises the server certificate.
type Certificate struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	DNSNames []string  `json:"dns_names,omitempty"`
	NotAfter time.Time `json:"not_after"`
}

// FetchErrorKind classifies fetch failures.
type FetchErrorKind int

// Fetch error kinds.
const (
	FetchNetwork FetchErrorKind = iota + 1
	FetchCertificate
	FetchRedirect
	FetchStatus
	FetchTooLarge
	FetchForbiddenAddress
	FetchDNS
)

// FetchError describes why a policy could not be retrieved.
type FetchError struct {
	Kind FetchErrorKind
	Err  error
}

func (e *FetchError) Error() string { return e.Err.Error() }
func (e *FetchError) Unwrap() error { return e.Err }

// Fetcher retrieves policies.
type Fetcher interface {
	Fetch(ctx context.Context, domain string) (*Response, error)
}

// HTTPFetcher fetches policies over HTTPS, resolving the policy host through
// the scan's resolver.
type HTTPFetcher struct {
	Resolver dnsresolver.Resolver
	Timeout  time.Duration
	// RootCAs overrides the system roots (tests).
	RootCAs *x509.CertPool
	// Port overrides 443 (tests).
	Port string
	// AllowNonPublic permits connecting to private and loopback addresses
	// (tests). By default such addresses are refused so that a hostile DNS
	// zone cannot make the scanner issue requests into internal networks.
	AllowNonPublic bool
}

// PolicyURL returns the well-known policy URL for domain.
func PolicyURL(domain string) string {
	return "https://mta-sts." + strings.TrimSuffix(domain, ".") + "/.well-known/mta-sts.txt"
}

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context, domain string) (*Response, error) {
	host := "mta-sts." + dnsresolver.Trim(domain)
	resp := &Response{URL: PolicyURL(domain)}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	port := f.Port
	if port == "" {
		port = "443"
	}

	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		addrs, err := f.resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		d := &net.Dialer{Timeout: timeout}
		for _, a := range addrs {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, &FetchError{Kind: FetchNetwork, Err: lastErr}
	}
	transport := &http.Transport{
		DialContext: dial,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    f.RootCAs,
			ServerName: host,
		},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		DisableKeepAlives:      true,
		Proxy:                  nil,
		MaxResponseHeaderBytes: 32 << 10,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resp.URL, nil)
	if err != nil {
		return resp, &FetchError{Kind: FetchNetwork, Err: err}
	}
	req.Header.Set("User-Agent", "MailAuthProbe (+https://github.com/pan-dolina/MailAuthProbe)")
	httpResp, err := client.Do(req)
	if err != nil {
		// On a verification failure the presented certificate is still
		// useful to explain the problem.
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) && len(certErr.UnverifiedCertificates) > 0 {
			resp.Certificate = summarize(certErr.UnverifiedCertificates[0])
		}
		return resp, classify(err)
	}
	defer httpResp.Body.Close()
	if httpResp.TLS != nil && len(httpResp.TLS.PeerCertificates) > 0 {
		resp.Certificate = summarize(httpResp.TLS.PeerCertificates[0])
	}
	resp.StatusCode = httpResp.StatusCode
	resp.ContentType = httpResp.Header.Get("Content-Type")

	switch {
	case httpResp.StatusCode >= 300 && httpResp.StatusCode < 400:
		return resp, &FetchError{Kind: FetchRedirect, Err: fmt.Errorf("the server redirects to %q; MTA-STS policy fetches must not follow redirects", httpResp.Header.Get("Location"))}
	case httpResp.StatusCode != http.StatusOK:
		return resp, &FetchError{Kind: FetchStatus, Err: fmt.Errorf("HTTP status %d", httpResp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, MaxPolicySize+1))
	if err != nil {
		return resp, &FetchError{Kind: FetchNetwork, Err: err}
	}
	if len(body) > MaxPolicySize {
		return resp, &FetchError{Kind: FetchTooLarge, Err: fmt.Errorf("policy exceeds %d bytes", MaxPolicySize)}
	}
	resp.Body = string(body)
	return resp, nil
}

func summarize(c *x509.Certificate) *Certificate {
	return &Certificate{
		Subject:  c.Subject.String(),
		Issuer:   c.Issuer.String(),
		DNSNames: c.DNSNames,
		NotAfter: c.NotAfter.UTC(),
	}
}

func (f *HTTPFetcher) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	v4, err4 := f.Resolver.LookupA(ctx, host)
	v6, err6 := f.Resolver.LookupAAAA(ctx, host)
	addrs := append(v4, v6...)
	if len(addrs) == 0 {
		err := err4
		if err == nil {
			err = err6
		}
		if err == nil {
			err = fmt.Errorf("%s has no A or AAAA records", host)
		}
		return nil, &FetchError{Kind: FetchDNS, Err: err}
	}
	if f.AllowNonPublic {
		return addrs, nil
	}
	var public []netip.Addr
	for _, a := range addrs {
		if !netutil.IsNonPublic(a) {
			public = append(public, a)
		}
	}
	if len(public) == 0 {
		return nil, &FetchError{Kind: FetchForbiddenAddress, Err: fmt.Errorf("%s resolves only to non-public addresses (%v); refusing to connect", host, addrs)}
	}
	return public, nil
}

func classify(err error) error {
	var fe *FetchError
	if errors.As(err, &fe) {
		return fe
	}
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknownAuth x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &unknownAuth) || errors.As(err, &invalid) {
		return &FetchError{Kind: FetchCertificate, Err: err}
	}
	return &FetchError{Kind: FetchNetwork, Err: err}
}

// isTextPlain reports whether a Content-Type header denotes text/plain.
func isTextPlain(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "text/plain"
}
