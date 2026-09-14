// Command archive creates deterministic release archives: entries are
// sorted, owned by 0:0, have fixed permissions and carry the modification
// time given by -mtime (normally SOURCE_DATE_EPOCH), and the gzip header
// contains no timestamp or file name.
//
//	go run ./internal/tools/archive -o out.tar.gz -mtime 1789380000 name=path ...
//
// The format is chosen from the output extension: .tar.gz or .zip.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/flate"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

type entry struct {
	name string // path inside the archive
	src  string // file on disk
	exec bool
}

func main() {
	out := flag.String("o", "", "output archive (.tar.gz or .zip)")
	mtime := flag.Int64("mtime", 0, "modification time for all entries (Unix seconds)")
	execNames := flag.String("exec", "", "comma-separated archive names that are executable")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: archive -o out.tar.gz -mtime N name=path ...")
		os.Exit(2)
	}
	executables := strings.Split(*execNames, ",")
	var entries []entry
	for _, arg := range flag.Args() {
		name, src, ok := strings.Cut(arg, "=")
		if !ok || name == "" || src == "" {
			fmt.Fprintf(os.Stderr, "archive: invalid entry %q (want name=path)\n", arg)
			os.Exit(2)
		}
		entries = append(entries, entry{name: name, src: src, exec: slices.Contains(executables, name)})
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })

	ts := time.Unix(*mtime, 0).UTC()
	var err error
	switch {
	case strings.HasSuffix(*out, ".tar.gz"):
		err = writeTarGz(*out, entries, ts)
	case strings.HasSuffix(*out, ".zip"):
		err = writeZip(*out, entries, ts)
	default:
		err = errors.New("output must end in .tar.gz or .zip")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "archive:", err)
		os.Exit(1)
	}
}

func mode(e entry) int64 {
	if e.exec {
		return 0o755
	}
	return 0o644
}

func writeTarGz(path string, entries []entry, ts time.Time) (err error) {
	f, err := os.Create(path) // #nosec G304 -- release tooling writes to a path chosen by the caller
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		data, err := os.ReadFile(e.src) // #nosec G304 -- release tooling
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     mode(e),
			Size:     int64(len(data)),
			ModTime:  ts,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeZip(path string, entries []entry, ts time.Time) (err error) {
	f, err := os.Create(path) // #nosec G304 -- release tooling writes to a path chosen by the caller
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	zw := zip.NewWriter(f)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestCompression)
	})
	for _, e := range entries {
		data, err := os.ReadFile(e.src) // #nosec G304 -- release tooling
		if err != nil {
			return err
		}
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: ts}
		hdr.SetMode(os.FileMode(mode(e))) // #nosec G115 -- mode is 0644 or 0755
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return zw.Close()
}
