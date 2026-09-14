package dmarc

import "testing"

func TestOrganizationalDomain(t *testing.T) {
	tests := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"mail.example.com", "example.com"},
		{"a.b.c.example.com.", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"mail.example.co.uk", "example.co.uk"},
		{"co.uk", "co.uk"},
		{"com", "com"},
		{"user.github.io", "user.github.io"},
		{"www.user.github.io", "user.github.io"},
		{"mail.test.example", "test.example"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := OrganizationalDomain(tt.in); got != tt.want {
			t.Errorf("OrganizationalDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAligned(t *testing.T) {
	tests := []struct {
		name       string
		auth, from string
		relaxed    bool
		strict     bool
	}{
		{"identical", "example.com", "example.com", true, true},
		{"case and trailing dot", "Example.COM.", "example.com", true, true},
		{"auth subdomain", "mail.example.com", "example.com", true, false},
		{"from subdomain", "example.com", "news.example.com", true, false},
		{"sibling subdomains", "bounce.example.com", "news.example.com", true, false},
		{"different organizations", "example.net", "example.com", false, false},
		{"lookalike suffix", "notexample.com", "example.com", false, false},
		{"parent of org domain", "com", "example.com", false, false},
		{"multi-label public suffix", "mail.example.co.uk", "example.co.uk", true, false},
		{"different registrants under co.uk", "other.co.uk", "example.co.uk", false, false},
		{"private PSL entries are separate organizations", "alice.github.io", "bob.github.io", false, false},
		{"empty auth domain", "", "example.com", false, false},
		{"empty from domain", "example.com", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Aligned(tt.auth, tt.from, ModeRelaxed); got != tt.relaxed {
				t.Errorf("relaxed = %v, want %v", got, tt.relaxed)
			}
			if got := Aligned(tt.auth, tt.from, ModeStrict); got != tt.strict {
				t.Errorf("strict = %v, want %v", got, tt.strict)
			}
		})
	}
}
