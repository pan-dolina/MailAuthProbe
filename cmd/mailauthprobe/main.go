// Command mailauthprobe audits mail authentication configuration and analyses
// e-mail messages.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/marcindolinski/mailauthprobe/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.NewApp().Execute(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
