package spf

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
)

func check(t *testing.T, zone *dnstest.Zone, sender, ip string) *Evaluation {
	t.Helper()
	c := &Checker{Resolver: zone}
	return c.CheckHost(context.Background(), Request{IP: netip.MustParseAddr(ip), Sender: sender})
}

// includes builds a record with n include mechanisms, each pointing at a
// record that never matches.
func includesZone(n int) string {
	var b strings.Builder
	var terms []string
	for i := range n {
		fmt.Fprintf(&b, "inc%d.limits.test. TXT \"v=spf1 -all\"\n", i)
		terms = append(terms, fmt.Sprintf("include:inc%d.limits.test", i))
	}
	fmt.Fprintf(&b, "limits.test. TXT \"v=spf1 %s ip4:192.0.2.1 -all\"\n", strings.Join(terms, " "))
	return b.String()
}

func TestLookupLimit(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		want     Result
		lookups  int
		exceeded bool
	}{
		{"ten includes are allowed", includesZone(10), ResultPass, 10, false},
		{"eleventh include exceeds the limit", includesZone(11), ResultPermError, 11, true},
		{
			name: "non-DNS terms do not count",
			zone: `limits.test. TXT "v=spf1 ip4:198.51.100.1 ip4:198.51.100.2 ip6:2001:db8::1 ip6:2001:db8::2 ip4:198.51.100.3 ip4:198.51.100.4 ip4:198.51.100.5 ip4:198.51.100.6 ip4:198.51.100.7 ip4:198.51.100.8 ip4:198.51.100.9 ip4:192.0.2.1 -all exp=e.limits.test"`,
			want: ResultPass, lookups: 0,
		},
		{
			name: "nested includes count towards one budget",
			zone: `
limits.test.    TXT "v=spf1 include:l1.limits.test include:l2.limits.test ip4:192.0.2.1 -all"
l1.limits.test. TXT "v=spf1 a:x.limits.test a:x.limits.test a:x.limits.test a:x.limits.test -all"
l2.limits.test. TXT "v=spf1 mx:x.limits.test mx:x.limits.test mx:x.limits.test mx:x.limits.test mx:x.limits.test -all"
x.limits.test.  A   198.51.100.1
x.limits.test.  MX  10 x.limits.test.
`,
			want: ResultPermError, lookups: 11, exceeded: true,
		},
		{
			name: "redirect counts",
			zone: `
limits.test.    TXT "v=spf1 a:x.limits.test a:x.limits.test a:x.limits.test a:x.limits.test a:x.limits.test a:x.limits.test a:x.limits.test a:x.limits.test a:x.limits.test redirect=r.limits.test"
r.limits.test.  TXT "v=spf1 a:x.limits.test -all"
x.limits.test.  A   198.51.100.1
`,
			want: ResultPermError, lookups: 11, exceeded: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := check(t, dnstest.MustParseZone(tt.zone), "user@limits.test", "192.0.2.1")
			if ev.Result != tt.want {
				t.Fatalf("result = %s, want %s (%s)", ev.Result, tt.want, ev.Reason)
			}
			if tt.lookups != 0 || tt.want == ResultPass {
				if ev.Lookups != tt.lookups {
					t.Errorf("lookups = %d, want %d", ev.Lookups, tt.lookups)
				}
			}
			if ev.LookupLimitExceeded != tt.exceeded {
				t.Errorf("LookupLimitExceeded = %v, want %v", ev.LookupLimitExceeded, tt.exceeded)
			}
		})
	}
}

func TestMatchBeforeLimitIsNotAnError(t *testing.T) {
	// Terms after the matching directive are never evaluated, so a record
	// that would exceed the limit still passes for early matches.
	var terms []string
	for i := range 20 {
		terms = append(terms, fmt.Sprintf("a:h%d.limits.test", i))
	}
	zone := dnstest.MustParseZone(`limits.test. TXT "v=spf1 ip4:192.0.2.1 ` + strings.Join(terms, " ") + ` -all"`)
	ev := check(t, zone, "user@limits.test", "192.0.2.1")
	if ev.Result != ResultPass || ev.Lookups != 0 {
		t.Errorf("result = %s, lookups = %d", ev.Result, ev.Lookups)
	}
}

func TestVoidLookupLimit(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   Result
		voids  int
	}{
		{"two void lookups allowed", "v=spf1 a:gone1.void.test mx:gone2.void.test ip4:192.0.2.1 -all", ResultPass, 2},
		{"third void lookup is permerror", "v=spf1 a:gone1.void.test mx:gone2.void.test exists:gone3.void.test ip4:192.0.2.1 -all", ResultPermError, 3},
		{"NODATA counts as void", "v=spf1 a:nodata.void.test a:nodata.void.test a:nodata.void.test ip4:192.0.2.1", ResultPermError, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := dnstest.MustParseZone("void.test. TXT \"" + tt.record + "\"\nnodata.void.test. TXT \"exists\"")
			ev := check(t, zone, "user@void.test", "192.0.2.1")
			if ev.Result != tt.want || ev.VoidLookups != tt.voids {
				t.Errorf("result = %s, voids = %d; want %s, %d (%s)", ev.Result, ev.VoidLookups, tt.want, tt.voids, ev.Reason)
			}
		})
	}
}

func TestMXNameLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString(`mxlimit.test. TXT "v=spf1 mx -all"` + "\n")
	for i := range 11 {
		fmt.Fprintf(&b, "mxlimit.test. MX %d mx%d.mxlimit.test.\n", i, i)
		fmt.Fprintf(&b, "mx%d.mxlimit.test. A 198.51.100.%d\n", i, i+1)
	}
	ev := check(t, dnstest.MustParseZone(b.String()), "user@mxlimit.test", "198.51.100.1")
	if ev.Result != ResultPermError || !strings.Contains(ev.Reason, "11 MX records") {
		t.Errorf("result = %s (%s)", ev.Result, ev.Reason)
	}
}

func TestRecursionLoops(t *testing.T) {
	tests := []struct {
		name  string
		zone  string
		chain string
	}{
		{"self include", `loop.test. TXT "v=spf1 include:loop.test -all"`, "loop.test -> loop.test"},
		{"include loop", `
loop.test.   TXT "v=spf1 include:b.loop.test -all"
b.loop.test. TXT "v=spf1 include:c.loop.test -all"
c.loop.test. TXT "v=spf1 include:LOOP.test -all"
`, "loop.test -> b.loop.test -> c.loop.test -> LOOP.test"},
		{"redirect loop", `
loop.test.   TXT "v=spf1 redirect=b.loop.test"
b.loop.test. TXT "v=spf1 redirect=loop.test"
`, "loop.test -> b.loop.test -> loop.test"},
		{"mixed include and redirect loop", `
loop.test.   TXT "v=spf1 include:b.loop.test -all"
b.loop.test. TXT "v=spf1 redirect=loop.test"
`, "loop.test -> b.loop.test -> loop.test"},
		{"loop through macro", `
loop.test.   TXT "v=spf1 include:%{d} -all"
`, "loop.test -> loop.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := dnstest.MustParseZone(tt.zone)
			ev := check(t, zone, "user@loop.test", "192.0.2.1")
			if ev.Result != ResultPermError || !ev.LoopDetected {
				t.Fatalf("result = %s, loop = %v (%s)", ev.Result, ev.LoopDetected, ev.Reason)
			}
			if !strings.Contains(ev.Reason, tt.chain) {
				t.Errorf("reason %q does not show chain %q", ev.Reason, tt.chain)
			}
			if q := len(zone.Queries()); q > 10 {
				t.Errorf("loop detection issued %d queries", q)
			}
		})
	}
}

func TestRepeatedIncludeIsNotALoop(t *testing.T) {
	zone := dnstest.MustParseZone(`
dup.test.        TXT "v=spf1 include:shared.dup.test include:shared.dup.test ip4:192.0.2.1 -all"
shared.dup.test. TXT "v=spf1 -all"
`)
	ev := check(t, zone, "user@dup.test", "192.0.2.1")
	if ev.Result != ResultPass || ev.LoopDetected || ev.Lookups != 2 {
		t.Errorf("result = %s, loop = %v, lookups = %d", ev.Result, ev.LoopDetected, ev.Lookups)
	}
}

func TestLongIncludeChainIsBounded(t *testing.T) {
	var b strings.Builder
	for i := range 50 {
		fmt.Fprintf(&b, "c%d.chain.test. TXT \"v=spf1 include:c%d.chain.test -all\"\n", i, i+1)
	}
	zone := dnstest.MustParseZone(b.String())
	ev := check(t, zone, "user@c0.chain.test", "192.0.2.1")
	if ev.Result != ResultPermError || !ev.LookupLimitExceeded {
		t.Fatalf("result = %s, exceeded = %v (%s)", ev.Result, ev.LookupLimitExceeded, ev.Reason)
	}
	if q := len(zone.Queries()); q != 11 {
		t.Errorf("queries = %d, want 11 (the initial record plus 10 includes)", q)
	}
}

func TestCustomLimits(t *testing.T) {
	zone := dnstest.MustParseZone(includesZone(3))
	c := &Checker{Resolver: zone, Limits: Limits{MaxLookups: 2, MaxVoidLookups: 2, MaxMXNames: 10, MaxPTRNames: 10, MaxDepth: 16}}
	ev := c.CheckHost(context.Background(), Request{IP: netip.MustParseAddr("192.0.2.1"), Sender: "a@limits.test"})
	if ev.Result != ResultPermError || !ev.LookupLimitExceeded {
		t.Errorf("result = %s", ev.Result)
	}
}
