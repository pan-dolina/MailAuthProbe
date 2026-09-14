package dkim

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Key types.
const (
	KeyTypeRSA     = "rsa"
	KeyTypeEd25519 = "ed25519"
)

// KeyRecord is a parsed DKIM public key record (RFC 6376 section 3.6.1).
type KeyRecord struct {
	Raw      string   `json:"raw"`
	Version  string   `json:"version,omitempty"`
	HashAlgs []string `json:"hash_algorithms,omitempty"`
	KeyType  string   `json:"key_type"`
	Notes    string   `json:"notes,omitempty"`
	Services []string `json:"services"`
	Flags    []string `json:"flags,omitempty"`
	// Revoked is set when p is empty.
	Revoked bool `json:"revoked"`
	// KeyBits is the RSA modulus size or 256 for Ed25519.
	KeyBits int `json:"key_bits,omitempty"`
	// PKCS1 is set when an RSA key was published as a bare RSAPublicKey
	// instead of SubjectPublicKeyInfo.
	PKCS1       bool     `json:"pkcs1,omitempty"`
	UnknownTags []string `json:"unknown_tags,omitempty"`

	PublicKey any `json:"-"`
}

// Testing reports whether the t=y flag is set.
func (k *KeyRecord) Testing() bool { return slices.Contains(k.Flags, "y") }

// StrictIdentity reports whether the t=s flag is set: the i= domain of a
// signature must equal d= exactly.
func (k *KeyRecord) StrictIdentity() bool { return slices.Contains(k.Flags, "s") }

// AllowsEmail reports whether the key may be used for e-mail signatures.
func (k *KeyRecord) AllowsEmail() bool {
	return slices.Contains(k.Services, "*") || slices.Contains(k.Services, "email")
}

// AllowsHash reports whether the key permits the hash algorithm.
func (k *KeyRecord) AllowsHash(h string) bool {
	return len(k.HashAlgs) == 0 || slices.Contains(k.HashAlgs, h)
}

// ParseKeyRecord parses a DKIM key TXT record. A revoked key (empty p=)
// parses successfully with Revoked set.
func ParseKeyRecord(txt string) (*KeyRecord, error) {
	tags, err := parseTagList(txt)
	if err != nil {
		return nil, err
	}
	k := &KeyRecord{Raw: txt, KeyType: KeyTypeRSA, Services: []string{"*"}}
	var p *string
	for i, t := range tags {
		switch t.name {
		case "v":
			if i != 0 {
				return nil, errors.New(`the v tag must be the first tag`)
			}
			if t.value != "DKIM1" {
				return nil, fmt.Errorf("unsupported version %q", t.value)
			}
			k.Version = t.value
		case "h":
			k.HashAlgs = splitList(strings.ToLower(t.value))
		case "k":
			k.KeyType = strings.ToLower(t.value)
		case "n":
			k.Notes = t.value
		case "p":
			v := stripFWS(t.value)
			p = &v
		case "s":
			k.Services = splitList(strings.ToLower(t.value))
		case "t":
			k.Flags = splitList(strings.ToLower(t.value))
		default:
			k.UnknownTags = append(k.UnknownTags, t.name)
		}
	}
	if p == nil {
		return nil, errors.New("required tag p is missing")
	}
	if *p == "" {
		k.Revoked = true
		return k, nil
	}
	der, err := base64.StdEncoding.DecodeString(*p)
	if err != nil {
		return nil, fmt.Errorf("p is not valid base64: %w", err)
	}
	switch k.KeyType {
	case KeyTypeRSA:
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			pk1, err1 := x509.ParsePKCS1PublicKey(der)
			if err1 != nil {
				return nil, fmt.Errorf("p is not a valid RSA public key: %w", err)
			}
			pub = pk1
			k.PKCS1 = true
		}
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("k=rsa but p contains a %T", pub)
		}
		k.PublicKey = rsaKey
		k.KeyBits = rsaKey.N.BitLen()
	case KeyTypeEd25519:
		if len(der) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 key must be %d bytes, got %d", ed25519.PublicKeySize, len(der))
		}
		k.PublicKey = ed25519.PublicKey(der)
		k.KeyBits = 256
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.KeyType)
	}
	return k, nil
}
