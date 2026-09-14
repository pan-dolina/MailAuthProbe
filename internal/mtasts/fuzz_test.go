package mtasts

import "testing"

func FuzzParsePolicy(f *testing.F) {
	f.Add("version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n")
	f.Add("version: STSv1\nmode: none\nmax_age: 0\n")
	f.Add(":\n::\n")
	f.Fuzz(func(t *testing.T, body string) {
		p, err := ParsePolicy(body)
		if err != nil {
			return
		}
		if p.MaxAge < 0 || p.MaxAge > MaxMaxAge {
			t.Fatalf("max_age %d out of range", p.MaxAge)
		}
		_ = p.Covers("mx1.example.com")
	})
}

func FuzzParseRecord(f *testing.F) {
	f.Add("v=STSv1; id=20260914;")
	f.Fuzz(func(t *testing.T, txt string) {
		if r, err := ParseRecord(txt); err == nil && r.ID == "" {
			t.Fatal("record without id accepted")
		}
	})
}
