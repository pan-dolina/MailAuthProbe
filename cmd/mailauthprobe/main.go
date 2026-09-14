// Command mailauthprobe audits mail authentication configuration and analyses
// e-mail messages.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/pan-dolina/mailauthprobe/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	// After the first interrupt, restore default signal handling so that a
	// second Ctrl-C terminates immediately.
	context.AfterFunc(ctx, stop)
	code := cli.NewApp().Execute(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
