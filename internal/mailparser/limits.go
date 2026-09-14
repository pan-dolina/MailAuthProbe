package mailparser

import "fmt"

// Limits bound the resources spent on a single message.
type Limits struct {
	// MaxMessageBytes caps the total input size.
	MaxMessageBytes int64
	// MaxHeaderBytes caps the size of the header section.
	MaxHeaderBytes int
	// MaxHeaders caps the number of header fields.
	MaxHeaders int
	// MaxMIMEDepth caps multipart nesting.
	MaxMIMEDepth int
	// MaxMIMEParts caps the total number of MIME parts examined.
	MaxMIMEParts int
}

// DefaultLimits are generous for legitimate mail and small enough to process
// hostile input safely.
var DefaultLimits = Limits{
	MaxMessageBytes: 50 << 20,
	MaxHeaderBytes:  512 << 10,
	MaxHeaders:      1000,
	MaxMIMEDepth:    20,
	MaxMIMEParts:    500,
}

func (l Limits) withDefaults() Limits {
	if l.MaxMessageBytes <= 0 {
		l.MaxMessageBytes = DefaultLimits.MaxMessageBytes
	}
	if l.MaxHeaderBytes <= 0 {
		l.MaxHeaderBytes = DefaultLimits.MaxHeaderBytes
	}
	if l.MaxHeaders <= 0 {
		l.MaxHeaders = DefaultLimits.MaxHeaders
	}
	if l.MaxMIMEDepth <= 0 {
		l.MaxMIMEDepth = DefaultLimits.MaxMIMEDepth
	}
	if l.MaxMIMEParts <= 0 {
		l.MaxMIMEParts = DefaultLimits.MaxMIMEParts
	}
	return l
}

// LimitError reports input that exceeds a hard limit. Such input is not
// analysed further.
type LimitError struct {
	Limit string
	Max   int64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("message exceeds the %s limit of %d", e.Limit, e.Max)
}
