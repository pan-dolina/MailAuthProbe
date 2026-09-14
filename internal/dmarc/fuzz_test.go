package dmarc

import "testing"

func FuzzParseDMARC(f *testing.F) {
	for _, s := range []string{
		"v=DMARC1; p=reject",
		"v=DMARC1; p=quarantine; sp=none; pct=25; adkim=s; aspf=s; rua=mailto:a@example.com!10m,mailto:b@example.net; ruf=mailto:f@example.com; fo=1:d:s; rf=afrf; ri=3600",
		"v=DMARC1; rua=mailto:d@example.com",
		"v=DMARC1;;;p=none;p=reject;foo=bar",
		"v = DMARC1 ; p = none ; rua = https://x",
		"v=DMARC1; p=none; rua=mailto:%40@@",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, record string) {
		rec, err := Parse(record)
		if err != nil {
			return
		}
		if rec.Policy.Strength() == 0 {
			t.Fatalf("valid record with invalid policy %q", rec.Policy)
		}
		if rec.Percent < 0 || rec.Percent > 100 {
			t.Fatalf("pct %d out of range", rec.Percent)
		}
		if rec.ADKIM != ModeRelaxed && rec.ADKIM != ModeStrict || rec.ASPF != ModeRelaxed && rec.ASPF != ModeStrict {
			t.Fatalf("invalid alignment modes %q %q", rec.ADKIM, rec.ASPF)
		}
		_ = rec.EffectiveSubdomainPolicy()
	})
}

func FuzzAlignment(f *testing.F) {
	f.Add("mail.example.co.uk", "example.co.uk")
	f.Add("..", "")
	f.Fuzz(func(t *testing.T, a, b string) {
		if Aligned(a, b, ModeStrict) && !Aligned(a, b, ModeRelaxed) {
			t.Fatal("strict alignment must imply relaxed alignment")
		}
		if Aligned(a, b, ModeRelaxed) != Aligned(b, a, ModeRelaxed) {
			t.Fatal("relaxed alignment must be symmetric")
		}
	})
}
