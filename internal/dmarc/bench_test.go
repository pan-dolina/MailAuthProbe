package dmarc

import "testing"

func BenchmarkParse(b *testing.B) {
	const record = "v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; rua=mailto:a@example.com!10m,mailto:b@example.net; ruf=mailto:f@example.com; fo=1:d"
	for b.Loop() {
		if _, err := Parse(record); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOrganizationalDomain(b *testing.B) {
	for b.Loop() {
		OrganizationalDomain("mail.eu.example.co.uk")
	}
}
