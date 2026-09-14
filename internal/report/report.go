// Package report defines the report model shared by all output formats and
// renders it as human-readable text or versioned JSON.
package report

import (
	"github.com/pan-dolina/mailauthprobe/internal/arc"
	"github.com/pan-dolina/mailauthprobe/internal/authres"
	"github.com/pan-dolina/mailauthprobe/internal/dkim"
	"github.com/pan-dolina/mailauthprobe/internal/dmarc"
	"github.com/pan-dolina/mailauthprobe/internal/findings"
	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
	"github.com/pan-dolina/mailauthprobe/internal/mtasts"
	"github.com/pan-dolina/mailauthprobe/internal/mx"
	"github.com/pan-dolina/mailauthprobe/internal/received"
	"github.com/pan-dolina/mailauthprobe/internal/spf"
	"github.com/pan-dolina/mailauthprobe/internal/tlsrpt"
)

// SchemaVersion identifies the JSON report format. It changes only for
// incompatible changes; adding fields is compatible.
const SchemaVersion = "1"

// Report kinds.
const (
	KindDomain  = "domain"
	KindMessage = "message"
	KindHeaders = "headers"
)

// Error kinds.
const (
	ErrorDNS   = "dns"
	ErrorInput = "input"
)

// Report is the complete result of one scan.
type Report struct {
	SchemaVersion string             `json:"schema_version"`
	Tool          Tool               `json:"tool"`
	Kind          string             `json:"kind"`
	Target        string             `json:"target"`
	Summary       Summary            `json:"summary"`
	Domain        *Domain            `json:"domain,omitempty"`
	Message       *Message           `json:"message,omitempty"`
	Findings      []findings.Finding `json:"findings"`
	Errors        []Error            `json:"errors"`
}

// Tool identifies the producer of the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Summary aggregates findings.
type Summary struct {
	// HighestSeverity is the most severe finding, or "none".
	HighestSeverity string         `json:"highest_severity"`
	Counts          map[string]int `json:"counts"`
	DNSQueries      int            `json:"dns_queries"`
}

// Error is a condition that made the scan incomplete.
type Error struct {
	Kind      string `json:"kind"`
	Component string `json:"component"`
	Message   string `json:"message"`
}

// Domain holds the details of a domain assessment.
type Domain struct {
	Name   string             `json:"name"`
	MX     *mx.Result         `json:"mx,omitempty"`
	SPF    *spf.Analysis      `json:"spf,omitempty"`
	DKIM   *dkim.Assessment   `json:"dkim,omitempty"`
	DMARC  *dmarc.Assessment  `json:"dmarc,omitempty"`
	MTASTS *mtasts.Assessment `json:"mta_sts,omitempty"`
	TLSRPT *tlsrpt.Assessment `json:"tls_rpt,omitempty"`
}

// Message holds the details of a message analysis.
type Message struct {
	Size          int                      `json:"size"`
	HeaderSize    int                      `json:"header_size"`
	BodyAvailable bool                     `json:"body_available"`
	Headers       MessageHeaders           `json:"headers"`
	MIME          *mailparser.Part         `json:"mime,omitempty"`
	Defects       []mailparser.Defect      `json:"defects,omitempty"`
	Received      *received.Chain          `json:"received"`
	SPF           *spf.MessageCheck        `json:"spf"`
	DKIM          []dkim.Verification      `json:"dkim"`
	DMARC         *dmarc.MessageEvaluation `json:"dmarc"`
	AuthResults   []authres.Parsed         `json:"authentication_results"`
	ReceivedSPF   []authres.ReceivedSPF    `json:"received_spf,omitempty"`
	ARC           *arc.Summary             `json:"arc,omitempty"`
}

// MessageHeaders are the identity and metadata headers of a message. Fields
// that appear more than once contain every value.
type MessageHeaders struct {
	From        []string `json:"from,omitempty"`
	Sender      []string `json:"sender,omitempty"`
	ReplyTo     []string `json:"reply_to,omitempty"`
	ReturnPath  []string `json:"return_path,omitempty"`
	To          []string `json:"to,omitempty"`
	Subject     []string `json:"subject,omitempty"`
	MessageID   []string `json:"message_id,omitempty"`
	Date        []string `json:"date,omitempty"`
	MIMEVersion []string `json:"mime_version,omitempty"`
	ContentType []string `json:"content_type,omitempty"`
}

// Finalize sorts findings and computes the summary. Call it once all
// findings have been added.
func (r *Report) Finalize(dnsQueries int) {
	if r.Findings == nil {
		r.Findings = []findings.Finding{}
	}
	if r.Errors == nil {
		r.Errors = []Error{}
	}
	findings.Sort(r.Findings)
	r.Summary.Counts = findings.Counts(r.Findings)
	r.Summary.HighestSeverity = "none"
	if m := findings.Max(r.Findings); m.Valid() {
		r.Summary.HighestSeverity = m.String()
	}
	r.Summary.DNSQueries = dnsQueries
}

// HasErrorKind reports whether the report contains an error of kind.
func (r *Report) HasErrorKind(kind string) bool {
	for _, e := range r.Errors {
		if e.Kind == kind {
			return true
		}
	}
	return false
}
