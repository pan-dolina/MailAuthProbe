package report

import (
	"encoding/json"
	"io"
)

// WriteJSON writes rep as indented JSON followed by a newline.
func WriteJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}
