// Command testdns serves a dnstest zone file on localhost for manual testing
// and smoke tests:
//
//	go run ./internal/tools/testdns -zone testdata/dns/zone.txt -addr 127.0.0.1:5353
//
// It prints the listening address on the first line of standard output and
// runs until interrupted.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
)

func main() {
	zonePath := flag.String("zone", "testdata/dns/zone.txt", "zone file")
	addr := flag.String("addr", "127.0.0.1:0", "listen address (UDP and TCP)")
	flag.Parse()

	data, err := os.ReadFile(*zonePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testdns:", err)
		os.Exit(1)
	}
	zone, err := dnstest.ParseZone(string(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, "testdns:", err)
		os.Exit(1)
	}
	srv, err := dnstest.Listen(zone, *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testdns:", err)
		os.Exit(1)
	}
	fmt.Println(srv.Addr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	_ = srv.Close()
}
