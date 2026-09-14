package dkim_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dkim"
	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/marcindolinski/mailauthprobe/internal/mailparser"
)

func loadFixture(t *testing.T, name string) (*mailparser.Message, *dnstest.Zone) {
	t.Helper()
	root := filepath.Join("..", "..", "testdata")
	zoneText, err := os.ReadFile(filepath.Join(root, "dns", "zone.txt"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "messages", name))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mailparser.ParseBytes(raw, mailparser.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return msg, dnstest.MustParseZone(string(zoneText))
}

func TestFixtures(t *testing.T) {
	tests := []struct {
		file    string
		results []dkim.Result
		failure []string
	}{
		{"valid.eml", []dkim.Result{dkim.ResultPass}, []string{""}},
		{"dkim-signature-mismatch.eml", []dkim.Result{dkim.ResultFail}, []string{dkim.FailSignature}},
		{"dkim-body-hash-mismatch.eml", []dkim.Result{dkim.ResultFail}, []string{dkim.FailBodyHash}},
		{"dkim-multiple.eml", []dkim.Result{dkim.ResultPermError, dkim.ResultPass, dkim.ResultPass}, []string{dkim.FailKeyNotFound, "", ""}},
		{"no-dkim.eml", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			msg, zone := loadFixture(t, tt.file)
			vs := dkim.VerifyMessage(context.Background(), zone, msg, dkim.VerifyOptions{Now: time.Unix(1789380000, 0)})
			if len(vs) != len(tt.results) {
				t.Fatalf("got %d verifications, want %d", len(vs), len(tt.results))
			}
			for i, v := range vs {
				if v.Result != tt.results[i] || v.Failure != tt.failure[i] {
					t.Errorf("signature %d (d=%s s=%s): %s/%s (%s), want %s/%s", i+1, v.Domain, v.Selector, v.Result, v.Failure, v.Reason, tt.results[i], tt.failure[i])
				}
			}
		})
	}
}
