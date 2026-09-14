// Command fixturegen regenerates the message fixtures in testdata/messages
// and the DNS zone in testdata/dns.
//
// Output is deterministic: RSA PKCS #1 v1.5 and Ed25519 signatures do not
// depend on randomness, and all timestamps are fixed. Run from the
// repository root:
//
//	go run ./internal/tools/fixturegen
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	files, err := Generate(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixturegen:", err)
		os.Exit(1)
	}
	for _, f := range files {
		path := filepath.Join(*root, f.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			fmt.Fprintln(os.Stderr, "fixturegen:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, f.Data, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "fixturegen:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", f.Path)
	}
}
