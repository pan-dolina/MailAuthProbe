// Package dkimtest signs messages for tests and fixture generation.
//
// It is not a general-purpose DKIM signer: it exists so that test fixtures
// can be regenerated deterministically and so that negative cases (bad body
// hashes, mismatching keys) can be produced on purpose.
package dkimtest

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- used to create rsa-sha1 test signatures
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"github.com/pan-dolina/mailauthprobe/internal/dkim"
	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
)

// Options describe the signature to create.
type Options struct {
	Domain    string
	Selector  string
	Signer    crypto.Signer // *rsa.PrivateKey or ed25519.PrivateKey
	Hash      string        // "sha256" (default) or "sha1"
	Headers   []string      // defaults to From:To:Subject:Date:Message-ID
	Canon     string        // e.g. "relaxed/relaxed"; default "relaxed/relaxed"
	AUID      string
	Timestamp int64
	Expire    int64
	// BodyLength sets l= to the full canonical body length when 0 < value,
	// or to the given value when >= 0 and BodyLengthSet.
	BodyLength    int64
	BodyLengthSet bool
	// ExtraTags are appended verbatim before b=.
	ExtraTags string
}

// Sign returns message with a DKIM-Signature header prepended. Line endings
// in message must be CRLF.
func Sign(message []byte, opts Options) ([]byte, error) {
	msg, err := mailparser.ParseBytes(message, mailparser.Options{})
	if err != nil {
		return nil, err
	}
	if opts.Hash == "" {
		opts.Hash = "sha256"
	}
	if opts.Canon == "" {
		opts.Canon = "relaxed/relaxed"
	}
	if len(opts.Headers) == 0 {
		opts.Headers = []string{"From", "To", "Subject", "Date", "Message-ID"}
	}
	hc, bc, _ := strings.Cut(opts.Canon, "/")
	if bc == "" {
		bc = dkim.CanonSimple
	}

	var newHash func() hash.Hash
	var hashFn crypto.Hash
	switch opts.Hash {
	case "sha256":
		newHash, hashFn = sha256.New, crypto.SHA256
	case "sha1":
		newHash, hashFn = sha1.New, crypto.SHA1
	default:
		return nil, fmt.Errorf("unsupported hash %q", opts.Hash)
	}
	var keyAlg string
	switch opts.Signer.(type) {
	case *rsa.PrivateKey:
		keyAlg = "rsa"
	case ed25519.PrivateKey:
		keyAlg = "ed25519"
	default:
		return nil, fmt.Errorf("unsupported signer %T", opts.Signer)
	}

	bh := newHash()
	limit := int64(-1)
	if opts.BodyLengthSet {
		limit = opts.BodyLength
	}
	total := dkim.CanonicalBody(bh, msg.Body, bc, limit)
	if opts.BodyLengthSet && opts.BodyLength < 0 {
		opts.BodyLength = total
	}

	var tags strings.Builder
	fmt.Fprintf(&tags, "v=1; a=%s-%s; c=%s; d=%s; s=%s;\r\n\t", keyAlg, opts.Hash, opts.Canon, opts.Domain, opts.Selector)
	if opts.AUID != "" {
		fmt.Fprintf(&tags, "i=%s; ", opts.AUID)
	}
	if opts.Timestamp != 0 {
		fmt.Fprintf(&tags, "t=%d; ", opts.Timestamp)
	}
	if opts.Expire != 0 {
		fmt.Fprintf(&tags, "x=%d; ", opts.Expire)
	}
	if opts.BodyLengthSet {
		fmt.Fprintf(&tags, "l=%d; ", opts.BodyLength)
	}
	fmt.Fprintf(&tags, "h=%s;\r\n\tbh=%s;\r\n\t%sb=", strings.Join(opts.Headers, ":"), base64.StdEncoding.EncodeToString(bh.Sum(nil)), opts.ExtraTags)
	unsigned := "DKIM-Signature: " + tags.String() + "\r\n"

	hh := newHash()
	used := map[int]bool{}
	for _, name := range opts.Headers {
		for i := len(msg.Headers) - 1; i >= 0; i-- {
			if !used[i] && strings.EqualFold(msg.Headers[i].Name, name) {
				used[i] = true
				hh.Write(dkim.CanonicalHeader(msg.Headers[i].Raw, hc))
				break
			}
		}
	}
	hh.Write(bytes.TrimSuffix(dkim.CanonicalHeader([]byte(unsigned), hc), []byte("\r\n")))
	digest := hh.Sum(nil)

	var sig []byte
	switch k := opts.Signer.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, hashFn, digest)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, digest)
	}
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(sig)
	var folded strings.Builder
	for i := 0; i < len(b64); i += 64 {
		if i > 0 {
			folded.WriteString("\r\n\t ")
		}
		folded.WriteString(b64[i:min(i+64, len(b64))])
	}
	header := strings.TrimSuffix(unsigned, "\r\n") + folded.String() + "\r\n"
	return append([]byte(header), message...), nil
}

// PublicKeyRecord returns the DNS TXT value for the signer's public key.
func PublicKeyRecord(signer crypto.Signer) (string, error) {
	switch k := signer.(type) {
	case *rsa.PrivateKey:
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return "", err
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
	case ed25519.PrivateKey:
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), nil
	}
	return "", fmt.Errorf("unsupported signer %T", signer)
}
