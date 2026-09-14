package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/pan-dolina/mailauthprobe/internal/version"
)

func (a *App) newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			if a.opts.json {
				enc := json.NewEncoder(a.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(info); err != nil {
					return withCode(ExitInternal, err)
				}
				return nil
			}
			fmt.Fprintf(a.Stdout, "mailauthprobe %s\n", info.Version)
			if info.Commit != "" {
				commit := info.Commit
				if info.Modified {
					commit += " (modified)"
				}
				fmt.Fprintf(a.Stdout, "  commit:   %s\n", commit)
			}
			if info.Date != "" {
				fmt.Fprintf(a.Stdout, "  built:    %s\n", info.Date)
			}
			fmt.Fprintf(a.Stdout, "  go:       %s\n", info.GoVersion)
			fmt.Fprintf(a.Stdout, "  platform: %s\n", info.Platform)
			return nil
		},
	}
}
