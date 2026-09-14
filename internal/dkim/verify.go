package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- required to verify (and reject) legacy rsa-sha1 signatures
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver"
	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
)

// MaxSignatures bounds the number of DKIM-Signature fields verified per
// message.
const MaxSignatures = 10

// Result is a DKIM verification result using the Authentication-Results
// vocabulary (RFC 8601 section 2.7.1).
type Result string

// Results.
const (
	ResultNone      Result = "none"
	ResultPass      Result = "pass"
	ResultFail      Result = "fail"
	ResultNeutral   Result = "neutral"
	ResultPolicy    Result = "policy"
	ResultTempError Result = "temperror"
	ResultPermError Result = "permerror"
)

// Failure categories that explain a non-pass result.
const (
	FailSyntax            = "syntax"
	FailKeyNotFound       = "key-not-found"
	FailKeyInvalid        = "key-invalid"
	FailKeyRevoked        = "key-revoked"
	FailKeyUnsuitable     = "key-unsuitable"
	FailAlgorithm         = "unsupported-algorithm"
	FailInsecureAlgorithm = "insecure-algorithm"
	FailExpired           = "expired"
	FailBodyHash          = "body-hash-mismatch"
	FailSignature         = "signature-mismatch"
	FailDNS               = "dns-error"
)

// Verification is the outcome for one DKIM-Signature.
type Verification struct {
	Index            int        `json:"index"`
	Result           Result     `json:"result"`
	Failure          string     `json:"failure,omitempty"`
	Reason           string     `json:"reason"`
	Domain           string     `json:"domain,omitempty"`
	Selector         string     `json:"selector,omitempty"`
	Algorithm        string     `json:"algorithm,omitempty"`
	AUID             string     `json:"auid,omitempty"`
	Canonicalization string     `json:"canonicalization,omitempty"`
	SignedHeaders    []string   `json:"signed_headers,omitempty"`
	BodyLength       *int64     `json:"body_length,omitempty"`
	CanonicalBodyLen int64      `json:"canonical_body_length,omitempty"`
	Timestamp        *time.Time `json:"timestamp,omitempty"`
	Expiration       *time.Time `json:"expiration,omitempty"`
	// BodyHashOK and SignatureOK are nil when the check was not performed.
	BodyHashOK  *bool      `json:"body_hash_ok,omitempty"`
	SignatureOK *bool      `json:"signature_ok,omitempty"`
	KeyName     string     `json:"key_name,omitempty"`
	Key         *KeyRecord `json:"key,omitempty"`
	// HeaderB is the start of the b= value, for matching against
	// Authentication-Results header.b.
	HeaderB   string     `json:"header_b,omitempty"`
	Signature *Signature `json:"-"`
}

// VerifyOptions control verification.
type VerifyOptions struct {
	// Now is the verification time; zero means time.Now().
	Now time.Time
}

func boolPtr(b bool) *bool { return &b }

// VerifyMessage verifies every DKIM-Signature in msg, up to MaxSignatures.
// Signatures are processed in header order. When the message was parsed
// without a body (headers only), body hashes are not checked and a valid
// header signature yields "neutral".
func VerifyMessage(ctx context.Context, r dnsresolver.Resolver, msg *mailparser.Message, opts VerifyOptions) []Verification {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	sigHeaders := msg.Get("DKIM-Signature")
	if len(sigHeaders) > MaxSignatures {
		sigHeaders = sigHeaders[:MaxSignatures]
	}
	out := make([]Verification, 0, len(sigHeaders))
	keys := map[string]keyLookup{}
	for i, h := range sigHeaders {
		v := verifyOne(ctx, r, msg, h, opts, keys)
		v.Index = i + 1
		out = append(out, v)
	}
	return out
}

type keyLookup struct {
	key *KeyRecord
	v   Verification // failure template when key is nil
}

func verifyOne(ctx context.Context, r dnsresolver.Resolver, msg *mailparser.Message, h mailparser.Header, opts VerifyOptions, keys map[string]keyLookup) Verification {
	sig, err := ParseSignature(h)
	if err != nil {
		return Verification{Result: ResultPermError, Failure: FailSyntax, Reason: "invalid DKIM-Signature: " + err.Error()}
	}
	v := Verification{
		Domain:           sig.Domain,
		Selector:         sig.Selector,
		Algorithm:        sig.Algorithm,
		AUID:             sig.AUID,
		Canonicalization: sig.HeaderCanon + "/" + sig.BodyCanon,
		SignedHeaders:    sig.SignedHeaders,
		BodyLength:       sig.BodyLength,
		HeaderB:          sig.ShortB(12),
		KeyName:          KeyName(sig.Selector, sig.Domain),
		Signature:        sig,
	}
	if sig.Timestamp != nil {
		t := time.Unix(*sig.Timestamp, 0).UTC()
		v.Timestamp = &t
	}
	if sig.Expiration != nil {
		t := time.Unix(*sig.Expiration, 0).UTC()
		v.Expiration = &t
	}
	fail := func(result Result, failure, format string, args ...any) Verification {
		v.Result, v.Failure, v.Reason = result, failure, fmt.Sprintf(format, args...)
		return v
	}

	var hashFn crypto.Hash
	var newHash func() hash.Hash
	switch sig.HashAlgorithm {
	case "sha256":
		hashFn, newHash = crypto.SHA256, sha256.New
	case "sha1":
		hashFn, newHash = crypto.SHA1, sha1.New
	default:
		return fail(ResultPermError, FailAlgorithm, "unsupported hash algorithm %q", sig.HashAlgorithm)
	}
	if sig.KeyAlgorithm != KeyTypeRSA && sig.KeyAlgorithm != KeyTypeEd25519 {
		return fail(ResultPermError, FailAlgorithm, "unsupported signing algorithm %q", sig.Algorithm)
	}
	if sig.KeyAlgorithm == KeyTypeEd25519 && sig.HashAlgorithm != "sha256" {
		return fail(ResultPermError, FailAlgorithm, "unsupported signing algorithm %q", sig.Algorithm)
	}
	if sig.Expiration != nil && opts.Now.Unix() > *sig.Expiration {
		return fail(ResultPermError, FailExpired, "the signature expired at %s", v.Expiration.Format(time.RFC3339))
	}

	// Key retrieval, cached per selector/domain within the message.
	kl, ok := keys[v.KeyName]
	if !ok {
		kl = fetchKey(ctx, r, v.KeyName)
		keys[v.KeyName] = kl
	}
	if kl.key == nil {
		v.Result, v.Failure, v.Reason = kl.v.Result, kl.v.Failure, kl.v.Reason
		return v
	}
	key := kl.key
	v.Key = key
	switch {
	case key.Revoked:
		return fail(ResultPermError, FailKeyRevoked, "the key at %s has been revoked (empty p=)", v.KeyName)
	case key.KeyType != sig.KeyAlgorithm:
		return fail(ResultPermError, FailKeyUnsuitable, "signature algorithm %s does not match key type %s", sig.Algorithm, key.KeyType)
	case !key.AllowsHash(sig.HashAlgorithm):
		return fail(ResultPermError, FailKeyUnsuitable, "the key does not permit hash algorithm %s (h=%s)", sig.HashAlgorithm, strings.Join(key.HashAlgs, ":"))
	case !key.AllowsEmail():
		return fail(ResultPermError, FailKeyUnsuitable, "the key is not valid for e-mail (s=%s)", strings.Join(key.Services, ":"))
	case key.StrictIdentity() && !strings.EqualFold(auidDomain(sig.AUID), sig.Domain):
		return fail(ResultPermError, FailKeyUnsuitable, "the key requires i= to use exactly d=%s (t=s)", sig.Domain)
	}

	// Body hash.
	if msg.BodyAvailable {
		body := normalizeEOL(msg.Body)
		hb := newHash()
		limit := int64(-1)
		if sig.BodyLength != nil {
			limit = *sig.BodyLength
		}
		v.CanonicalBodyLen = canonBody(hb, body, sig.BodyCanon, limit)
		if sig.BodyLength != nil && *sig.BodyLength > v.CanonicalBodyLen {
			v.BodyHashOK = boolPtr(false)
			return fail(ResultFail, FailBodyHash, "l=%d is longer than the canonicalized body (%d bytes)", *sig.BodyLength, v.CanonicalBodyLen)
		}
		ok := subtle.ConstantTimeCompare(hb.Sum(nil), sig.BodyHash) == 1
		v.BodyHashOK = boolPtr(ok)
		if !ok {
			return fail(ResultFail, FailBodyHash, "the body hash does not match bh=; the body was modified after signing")
		}
	}

	// Header hash.
	hh := newHash()
	for _, raw := range selectHeaders(msg.Headers, sig.SignedHeaders) {
		hh.Write(canonHeader(raw, sig.HeaderCanon))
	}
	sigHeader := canonHeader(stripSignatureValue(h.Raw), sig.HeaderCanon)
	hh.Write(bytes.TrimSuffix(sigHeader, []byte("\r\n")))
	digest := hh.Sum(nil)

	var sigOK bool
	switch pub := key.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.KeyBits < 1024 {
			return fail(ResultPermError, FailKeyUnsuitable, "the RSA key is %d bits; keys shorter than 1024 bits must not be accepted (RFC 8301)", key.KeyBits)
		}
		sigOK = rsa.VerifyPKCS1v15(pub, hashFn, digest, sig.Signature) == nil
	case ed25519.PublicKey:
		sigOK = ed25519.Verify(pub, digest, sig.Signature)
	default:
		return fail(ResultPermError, FailKeyInvalid, "unsupported public key")
	}
	v.SignatureOK = boolPtr(sigOK)
	if !sigOK {
		return fail(ResultFail, FailSignature, "the signature does not verify; signed header fields were modified or the wrong key is published")
	}
	if sig.HashAlgorithm == "sha1" {
		return fail(ResultPermError, FailInsecureAlgorithm, "rsa-sha1 is cryptographically valid but must not be accepted (RFC 8301)")
	}
	if v.BodyHashOK == nil {
		return fail(ResultNeutral, "", "the header signature is valid; the body was not available to check bh=")
	}
	v.Result = ResultPass
	v.Reason = fmt.Sprintf("valid %s signature by %s (selector %s)", sig.Algorithm, sig.Domain, sig.Selector)
	return v
}

func auidDomain(auid string) string {
	return strings.TrimSuffix(auid[strings.LastIndexByte(auid, '@')+1:], ".")
}

func fetchKey(ctx context.Context, r dnsresolver.Resolver, name string) keyLookup {
	txts, err := r.LookupTXT(ctx, name)
	switch {
	case dnsresolver.IsNXDomain(err) || (err == nil && len(txts) == 0):
		return keyLookup{v: Verification{Result: ResultPermError, Failure: FailKeyNotFound, Reason: "no DKIM key record at " + name}}
	case err != nil && dnsresolver.KindOf(err) == dnsresolver.KindInvalidName:
		return keyLookup{v: Verification{Result: ResultPermError, Failure: FailKeyNotFound, Reason: "invalid key name " + name}}
	case err != nil:
		return keyLookup{v: Verification{Result: ResultTempError, Failure: FailDNS, Reason: "key lookup failed: " + err.Error()}}
	}
	key, err := ParseKeyRecord(txts[0])
	if err != nil {
		return keyLookup{v: Verification{Result: ResultPermError, Failure: FailKeyInvalid, Reason: fmt.Sprintf("invalid key record at %s: %v", name, err)}}
	}
	return keyLookup{key: key}
}

// selectHeaders returns the raw header fields named in h, choosing
// instances from the bottom of the header section upwards (RFC 6376
// section 5.4.2). Names without a remaining instance contribute nothing.
func selectHeaders(headers []mailparser.Header, names []string) [][]byte {
	used := make(map[int]bool)
	var out [][]byte
	for _, name := range names {
		for i := len(headers) - 1; i >= 0; i-- {
			if !used[i] && strings.EqualFold(headers[i].Name, name) {
				used[i] = true
				out = append(out, headers[i].Raw)
				break
			}
		}
	}
	return out
}
