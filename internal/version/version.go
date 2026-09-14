// Package version exposes build metadata for MailAuthProbe.
//
// Release builds set Version, Commit and Date through -ldflags. Development
// builds fall back to the module and VCS information embedded by the Go
// toolchain.
package version

import (
	"runtime"
	"runtime/debug"
)

// Values injected at link time, for example:
//
//	-X github.com/pan-dolina/mailauthprobe/internal/version.Version=v0.1.0
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	Modified  bool   `json:"modified,omitempty"`
}

// Get returns build information for the current binary.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	if info.Version == "" {
		info.Version = "devel"
	}
	return info
}
