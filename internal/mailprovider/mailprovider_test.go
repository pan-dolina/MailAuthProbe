package mailprovider

import (
	"reflect"
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name       string
		mx, spf    []string
		want       []string
		wantDetail []Match
	}{
		{name: "none", mx: []string{"mx1.example.com"}, spf: []string{"_spf.example.com"}},
		{
			name: "google by mx",
			mx:   []string{"ASPMX.L.GOOGLE.COM.", "alt1.aspmx.l.google.com"},
			wantDetail: []Match{{
				Provider: "Google Workspace", Evidence: "MX aspmx.l.google.com", DKIMSelectors: []string{"google"},
			}},
		},
		{
			name: "mx evidence wins over spf",
			mx:   []string{"example-com.mail.protection.outlook.com"},
			spf:  []string{"spf.protection.outlook.com"},
			wantDetail: []Match{{
				Provider: "Microsoft 365", Evidence: "MX example-com.mail.protection.outlook.com", DKIMSelectors: []string{"selector1", "selector2"},
			}},
		},
		{
			name: "note without selectors",
			spf:  []string{"amazonses.com"},
			wantDetail: []Match{{
				Provider: "Amazon SES", Evidence: "SPF include amazonses.com", DKIMNote: "Amazon SES (Easy DKIM) generates random selectors for each domain; they are shown in the SES console",
			}},
		},
		{name: "suffix boundary", mx: []string{"notgoogle.com", "google.com.evil.example"}, spf: []string{"x.sendgrid.net", "sendgrid.net.example"}},
		{name: "spf match is exact", spf: []string{"eu._spf.google.com"}},
		{
			name: "order follows the table",
			mx:   []string{"in1-smtp.messagingengine.com"},
			spf:  []string{"sendgrid.net", "_spf.google.com", "sendgrid.net"},
			want: []string{"Google Workspace", "SendGrid", "Fastmail"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.mx, tt.spf)
			if tt.wantDetail != nil || tt.want == nil {
				if !reflect.DeepEqual(got, tt.wantDetail) {
					t.Errorf("Detect() = %+v, want %+v", got, tt.wantDetail)
				}
				return
			}
			var names []string
			for _, m := range got {
				names = append(names, m.Provider)
			}
			if !reflect.DeepEqual(names, tt.want) {
				t.Errorf("providers = %v, want %v", names, tt.want)
			}
		})
	}
}

func TestDetectDoesNotShareSelectors(t *testing.T) {
	m := Detect(nil, []string{"_spf.google.com"})
	m[0].DKIMSelectors[0] = "changed"
	if Known[0].DKIMSelectors[0] != "google" {
		t.Error("Detect returned the provider table's selector slice")
	}
}

func TestKnownProviders(t *testing.T) {
	names := map[string]bool{}
	for _, p := range Known {
		if names[p.Name] {
			t.Errorf("duplicate provider %q", p.Name)
		}
		names[p.Name] = true
		if len(p.MXSuffixes)+len(p.SPFIncludes) == 0 {
			t.Errorf("%s: no detection rule", p.Name)
		}
		if (len(p.DKIMSelectors) == 0) == (p.DKIMNote == "") {
			t.Errorf("%s: want either DKIM selectors or a note explaining their absence", p.Name)
		}
		for _, s := range append(append([]string{}, p.MXSuffixes...), p.SPFIncludes...) {
			if s != normalize(s) {
				t.Errorf("%s: %q is not normalized", p.Name, s)
			}
		}
	}
}
