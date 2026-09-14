// Package arc summarises Authenticated Received Chain (RFC 8617) header
// sets. It checks the structure of the chain; it does not verify ARC
// signatures cryptographically.
package arc

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/pan-dolina/mailauthprobe/internal/findings"
	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
)

// MaxInstances is the largest instance number allowed by RFC 8617.
const MaxInstances = 50

// Set is one ARC instance.
type Set struct {
	Instance int    `json:"instance"`
	CV       string `json:"cv,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Selector string `json:"selector,omitempty"`
	// Present lists which of the three headers exist for this instance.
	Seal             bool `json:"arc_seal"`
	MessageSignature bool `json:"arc_message_signature"`
	AuthResults      bool `json:"arc_authentication_results"`
}

// Summary describes the ARC chain of a message.
type Summary struct {
	Sets     []Set              `json:"sets"`
	Valid    bool               `json:"structurally_valid"`
	Problems []string           `json:"problems,omitempty"`
	Findings []findings.Finding `json:"-"`
}

func instanceOf(value string) (int, map[string]string) {
	tags := map[string]string{}
	for part := range strings.SplitSeq(value, ";") {
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(val)
	}
	n, err := strconv.Atoi(tags["i"])
	if err != nil {
		return 0, tags
	}
	return n, tags
}

// Summarize inspects the ARC headers of msg. It returns nil when the message
// has no ARC headers.
func Summarize(msg *mailparser.Message) *Summary {
	seals := msg.Get("ARC-Seal")
	sigs := msg.Get("ARC-Message-Signature")
	ars := msg.Get("ARC-Authentication-Results")
	if len(seals)+len(sigs)+len(ars) == 0 {
		return nil
	}
	s := &Summary{Sets: []Set{}}
	byInstance := map[int]*Set{}
	get := func(i int) *Set {
		if byInstance[i] == nil {
			byInstance[i] = &Set{Instance: i}
		}
		return byInstance[i]
	}
	problem := func(format string, args ...any) { s.Problems = append(s.Problems, fmt.Sprintf(format, args...)) }

	type entry struct {
		headers []mailparser.Header
		name    string
		mark    func(*Set, map[string]string) bool
	}
	for _, e := range []entry{
		{seals, "ARC-Seal", func(set *Set, tags map[string]string) bool {
			dup := set.Seal
			set.Seal, set.CV, set.Domain, set.Selector = true, strings.ToLower(tags["cv"]), tags["d"], tags["s"]
			return dup
		}},
		{sigs, "ARC-Message-Signature", func(set *Set, _ map[string]string) bool {
			dup := set.MessageSignature
			set.MessageSignature = true
			return dup
		}},
		{ars, "ARC-Authentication-Results", func(set *Set, _ map[string]string) bool {
			dup := set.AuthResults
			set.AuthResults = true
			return dup
		}},
	} {
		for _, h := range e.headers {
			i, tags := instanceOf(h.Value)
			if i < 1 || i > MaxInstances {
				problem("%s has an invalid instance number (i=%q)", e.name, tags["i"])
				continue
			}
			if e.mark(get(i), tags) {
				problem("instance %d has more than one %s header", i, e.name)
			}
		}
	}
	keys := make([]int, 0, len(byInstance))
	for k := range byInstance {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for idx, k := range keys {
		set := byInstance[k]
		s.Sets = append(s.Sets, *set)
		if k != idx+1 {
			problem("instance numbers are not consecutive from 1 (found %d at position %d)", k, idx+1)
		}
		if !set.Seal || !set.MessageSignature || !set.AuthResults {
			problem("instance %d is incomplete", k)
		}
		switch {
		case k == 1 && set.Seal && set.CV != "none":
			problem("instance 1 must have cv=none, found cv=%s", set.CV)
		case k > 1 && set.Seal && set.CV != "pass" && set.CV != "fail":
			problem("instance %d has invalid cv=%s", k, set.CV)
		}
	}
	s.Valid = len(s.Problems) == 0 && len(s.Sets) > 0

	if !s.Valid {
		s.Findings = append(s.Findings, findings.ARCInvalid.New("", "The ARC header set is structurally invalid; receivers treat the chain as failed.", s.Problems...))
		return s
	}
	last := s.Sets[len(s.Sets)-1]
	if last.CV == "fail" {
		s.Findings = append(s.Findings, findings.ARCFail.New(last.Domain, fmt.Sprintf("ARC instance %d (%s) recorded cv=fail: an intermediary found the chain broken.", last.Instance, last.Domain)))
	} else {
		s.Findings = append(s.Findings, findings.ARCPresent.New(last.Domain, fmt.Sprintf("The message carries an ARC chain with %d instance(s); the latest was added by %s. Signatures were not verified.", len(s.Sets), last.Domain)))
	}
	return s
}
