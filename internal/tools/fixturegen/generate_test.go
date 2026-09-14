package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestFixturesUpToDate fails when the committed fixtures differ from what
// the generator produces, so that fixtures never drift from their source.
func TestFixturesUpToDate(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	files, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(root, f.Path))
		if err != nil {
			t.Errorf("%s: %v (run: go run ./internal/tools/fixturegen)", f.Path, err)
			continue
		}
		if !bytes.Equal(got, f.Data) {
			t.Errorf("%s is out of date (run: go run ./internal/tools/fixturegen)", f.Path)
		}
	}
}
